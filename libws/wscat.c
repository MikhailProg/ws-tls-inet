#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include "common.h"
#include "inet.h"
#include "ws.h"

#define DEFAULT_URI	"/cat"
#define PING_TIMEOUT	3
#define CLOSE_TIMEOUT	5
#define EV_IN(e)	((e) & (POLLIN | POLLHUP))
#define EV_ERR(e)	((e) & (POLLNVAL | POLLERR))

static int	sigpipe[2];
static int	signals[NSIG];
static char	ping_buf[32];
static int	pong_wait;

struct loop_ctx {
	WebSocket	*ws;
	int		in;
	int		out;
	int		net;
	int		sig;
	const char	*host;
	const char	*uri;
};

static int fd_nonblock(int fd)
{
	int flags;
	return ((flags = fcntl(fd, F_GETFL)) < 0 ||
			 fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0);
}

static ssize_t sockrecv(void *opaque, void *buf, size_t n)
{
	ssize_t rc;
#if IOFUZZ
	n = 1 + rand() % n;
#endif
	rc = recv(*(int *)opaque, buf, n, 0);
	if (rc <= 0) {
		if (rc < 0 && SOFT_ERROR)
			return WS_E_WANT_READ;
		else if (!rc)
			return WS_E_EOF;
		else
			return WS_E_IO;
	}

	return rc;
}

static ssize_t socksend(void *opaque, const void *buf, size_t n)
{
	ssize_t rc;
#if IOFUZZ
	n = 1 + rand() % n;
#endif
	rc = send(*(int *)opaque, buf, n, 0);
	if (rc < 0) {
		if (rc < 0 && SOFT_ERROR)
			return WS_E_WANT_WRITE;
		else
			return WS_E_IO;
	}

	return rc;
}

static void wait_event(int fd, int r)
{
	struct pollfd fds;
	int rc;

	/* Schedule event. */
	fds.fd = fd;
	fds.events = r ? POLLIN : POLLOUT;
	do {
		rc = poll(&fds, 1, -1);
	} while (rc < 0 && errno == EINTR);
}

static ssize_t writeall(int fd, const void *buf, size_t len)
{
	size_t off = 0, m = len;
	ssize_t n;

	while (len) {
		if ((n = write(fd, buf + off, len)) < 0) {
			if (SOFT_ERROR)
				wait_event(fd, 0);
			else
				return n;
		} else {
			off += n;
			len -= n;
		}
	}

	return m;
}

static void sigall(int signo)
{
	unsigned char a = 42;

	signals[signo] = 1;
	write(sigpipe[1], &a, 1);
}

static void siginit(void)
{
	struct sigaction sa;
	int i;
	int sigs[] = {
		SIGALRM, SIGTERM, SIGINT, SIGHUP
	};

	if (pipe(sigpipe) < 0)
		ERR("pipe()");
	if (fd_nonblock(sigpipe[0]) < 0)
		ERR("fd_nonblock()");

	signal(SIGPIPE, SIG_IGN);

	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sigall;

	for (i = 0; i < (int)ARRSZ(sigs); i++)
		sigaction(sigs[i], &sa, NULL);
}

static void sigdrain(int fd)
{
	unsigned char buf[32];

	while (read(fd, buf, sizeof(buf)) > 0)
		;
}

static void half_close(const struct loop_ctx *ctx)
{
	const char msg[] = "wscat is gone!";
	int rc;

	if (ctx->in == -1)
		return;

	while ((rc = ws_close(ctx->ws, 1001, msg, sizeof(msg)-1)))
		if (rc == WS_E_WANT_WRITE)
			wait_event(ctx->net, 0);
		else
			ERRX("ws_close(): failed 0x%X", -rc);

	shutdown(ctx->net, SHUT_WR);
	/* Reset ping timer and set close timer it will terminate
	 * the process. */
	alarm(0);
	signals[SIGALRM] = 0;
	signal(SIGALRM, SIG_DFL);
	alarm(CLOSE_TIMEOUT);
}

static int sig_hnd(const struct loop_ctx *ctx)
{
	int i, rc, n = (int)sizeof(ping_buf);

	sigdrain(ctx->sig);

	if (signals[SIGALRM]) {
		signals[SIGALRM] = 0;

		if (pong_wait)
			ERRX("PONG is missed");

		for (i = 0; i < n; i++)
			ping_buf[i] = rand() % 256;

		while ((rc = ws_ping(ctx->ws, ping_buf, sizeof(ping_buf))))
			if (rc == WS_E_WANT_WRITE)
				wait_event(ctx->net, 0);
			else
				ERRX("ws_ping(): failed 0x%x", -rc);
		pong_wait = 1;
		/* Restart timer. */
		alarm(PING_TIMEOUT);
	} else if (signals[SIGTERM] || signals[SIGINT]) {
		signals[SIGTERM] = signals[SIGINT] = 0;
		half_close(ctx);
		return -1;
	}

	return 0;
}

static int coproc_hnd(const struct loop_ctx *ctx,
			unsigned char *utf8, size_t *off, size_t n)
{
	size_t o = *off;
	ssize_t m, rc;

	//m = read(ctx->in, utf8 + o, 1);
	m = read(ctx->in, utf8 + o, n - o);
	if (m <= 0) {
		if (m < 0 && SOFT_ERROR) {
			return 0;
		} else {
			half_close(ctx);
			return -1;
		}
	}

	m += o;

	for (;;) {
		rc = ws_txt_write(ctx->ws, utf8, m);
		if (rc < 0) {
			if (rc == WS_E_WANT_WRITE) {
				wait_event(ctx->net, 0);
			} else if (rc == WS_E_UTF8_INCOPMLETE) {
				assert(m < 4);
				o = m;
				break;
			} else if (rc == WS_E_NON_UTF8) {
				o = 0;
				break;
			} else {
				ERRX("ws_txt_write(): failed -0x%zX", -rc);
			}
		} else {
			o = m - rc;
			/* Partial UTF-8. */
			if (o > 0) {
				assert(o < 4);
				memmove(utf8, utf8 + rc, o);
			}
			break;
		}
	}

	*off = o;
	return 0;
}

static void ws_ctrl(const struct loop_ctx *ctx, int e)
{
	int rc;

	if (e == WS_E_OP_CLOSE) {
		/* WebSocket is already half_closed (can't write). */
		if (ctx->in == -1) {
			WARNX("WebSocket session is closed");
			exit(EXIT_SUCCESS);
		}
		/* Confirm close with received ecode. */
		while ((rc = ws_close(ctx->ws, ctx->ws->ecode, NULL, 0)))
			if (rc == WS_E_WANT_WRITE)
				wait_event(ctx->net, 0);
			else
				ERRX("ws_close(): failed 0x%X", -rc);
		/* WebSocket session is closed terminate the program. */
		WARNX("WebSocket session is closed");
		exit(EXIT_SUCCESS);
	} else if (e == WS_E_OP_PING) {
		/* WebSocket is already half_closed (can't write). */
		if (ctx->in == -1)
			return;
		/* Pong with Ping data. */
		while ((rc = ws_pong(ctx->ws, ctx->ws->ctrl, ctx->ws->ctrlsz)))
			if (rc == WS_E_WANT_WRITE)
				wait_event(ctx->net, 0);
			else
				ERRX("ws_pong(): failed 0x%X", -rc);
	} else if (e == WS_E_OP_PONG) {
		if (!pong_wait)
			return;
		pong_wait = 0;
		if (ctx->ws->ctrlsz != sizeof(ping_buf) ||
		    memcmp(ping_buf, ctx->ws->ctrl, ctx->ws->ctrlsz) != 0)
			WARNX("PONG doesn't match PING");
	}
}

static void
drain(void *opaque, const void *buf, size_t n, int txt)
{
	struct loop_ctx *ctx = opaque;

	if (!txt)
		ERRX("ws_parse(): non text data");
	if (writeall(ctx->out, buf, n) < 0)
		ERR("writeall()");
}

static void ws_hnd(const struct loop_ctx *ctx)
{
	unsigned char buf[256];
	ssize_t rc;
	int txt;

	for (;;) {
		/* Use both read and parse API. */
		rc = (rand() % 256 > 128) ?
			ws_read(ctx->ws, buf, sizeof(buf), &txt) :
			ws_parse(ctx->ws, (void *)ctx, drain);
		if (rc <= 0) {
			if (!rc)
				rc = WS_E_EOF;

			if (rc == WS_E_WANT_READ)
				break;
			else if (rc == WS_E_OP_CLOSE ||
				 rc == WS_E_OP_PING  ||
				 rc == WS_E_OP_PONG)
				ws_ctrl(ctx, rc);
			else
				ERRX("ws_read(): failed 0x%zX", -rc);
		} else {
			drain((void *)ctx, buf, rc, txt);
		}
	}
}

static void wscat(struct loop_ctx *ctx)
{
	struct pollfd fds[3];
	unsigned char utf8[16536];
	char uhdrs[128];
	size_t off = 0;
	ssize_t rc;

	/* Set some extra HTTP headers. */
	snprintf(uhdrs, sizeof(uhdrs),  "Header1: Value1\r\n"
					"Header2: Value2\r\n");
	while ((rc = ws_handshake(ctx->ws, ctx->host, ctx->uri, uhdrs)))
		if (rc == WS_E_WANT_READ || rc == WS_E_WANT_WRITE)
			wait_event(ctx->net, rc == WS_E_WANT_READ);
		else
			ERRX("ws_handshake(): failed -0x%zX", -rc);

	poll(NULL, 0, 100);
	fds[0].fd = ctx->sig;
	fds[0].events = POLLIN;
	fds[1].fd = ctx->in;
	fds[1].events = POLLIN;
	fds[2].fd = ctx->net;
	fds[2].events = POLLIN;
	alarm(PING_TIMEOUT);

	for (;;) {
		rc = poll(fds, 3, -1);
		if (rc < 0 && errno == EINTR)
			continue;
		else if (rc < 0)
			ERR("poll()");

		if (EV_IN(fds[0].revents)) {
			if (sig_hnd(ctx) < 0) {
				ctx->in = fds[1].fd = -1;
				fds[1].revents = 0;
			}
		}

		/* fd -> ws */
		if (EV_ERR(fds[1].revents)) {
			half_close(ctx);
			ctx->in = fds[1].fd = -1;
		} else if (EV_IN(fds[1].revents)) {
			if (coproc_hnd(ctx, utf8, &off, sizeof(utf8)) < 0)
				ctx->in = fds[1].fd = -1;
		}

		/* ws -> fd */
		if (EV_ERR(fds[2].revents))
			return;
		else if (EV_IN(fds[2].revents))
			ws_hnd(ctx);
	}
}

static void wscat_run(WebSocket *ws, int fd, const char *host, const char *uri)
{
	struct loop_ctx ctx;

	ws_set_bio(ws, &fd, socksend, sockrecv);
	siginit();
	ctx.ws   = ws;
	ctx.in   = STDIN_FILENO;
	ctx.out  = STDOUT_FILENO;
	ctx.net  = fd;
	ctx.sig  = sigpipe[0];
	ctx.host = host;
	ctx.uri  = uri;
	wscat(&ctx);
}

static void srv(const char *addr, const char *port,
		const char *host, const char *uri)
{
	struct sockaddr_storage ss;
	socklen_t slen;
	WebSocket ws;
	int fd, afd;

	if ((fd = tcp_listen(addr, port)) < 0)
		ERR("tcp_listen() failed");

	for (;;) {
		slen = sizeof(ss);
		afd = accept(fd, (struct sockaddr *)&ss, &slen);
		if (afd < 0) {
			if (!SOFT_ERROR)
				WARN("accept()");
			continue;
		}

		if (fd_nonblock(afd) < 0)
			ERR("fd_nonblock() failed");

		if (ws_init(&ws, 1) < 0)
			ERRX("ws_init() failed");

		close(fd);
		wscat_run(&ws, afd, host, uri);

		ws_deinit(&ws);
		close(afd);
		break;
	}
}

static void usr(const char *addr, const char *port,
		const char *host, const char *uri)
{
	WebSocket ws;
	int fd;

	if ((fd = tcp_connect(addr, port, 0)) < 0)
		ERR("tcp_connect() failed");

	if (fd_nonblock(fd) < 0)
		ERR("fd_nonblock() failed");

	if (ws_init(&ws, 0) < 0)
		ERRX("ws_init() failed");

	wscat_run(&ws, fd, host, uri);

	ws_deinit(&ws);
	close(fd);
}

static void usage(void)
{
	extern const char *const __progname;
	fprintf(stderr,
		"\nusage: [WS_SRV=] [WS_URI=/uri] %s dest port\n\n"
		"    WS_SRV and WS_URI are environment variables:\n"
		"    * WS_SRV starts the program as a server.\n"
		"    * WS_URI sets ws://dest:port/URI, default is '%s'.\n"
		"\n", __progname, DEFAULT_URI);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char host[1024];
	char *addr, *port, *uri;
	int n;

	if (argc < 3)
		usage();

	addr = argv[1];
	port = argv[2];

	srand(time(NULL));

	if ((n = atoi(port)) <= 0 || n > 65535)
		usage();

	snprintf(host, sizeof(host), "%s%s%s", addr,
			n != 80 ? ":": "", n != 80 ? port : "");

	uri = (uri = getenv("WS_URI")) ? uri : DEFAULT_URI;

	if (fd_nonblock(STDIN_FILENO) < 0)
		ERR("fd_nonblock() failed");

	(getenv("WS_SRV") ? srv : usr)(addr, port, host, uri);

	return EXIT_SUCCESS;
}

