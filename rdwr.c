#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <err.h>

#include <ws.h>
#include <inet.h>

#include <gnutls/gnutls.h>

#define UNIX_E_SOFT	(errno == EINTR || errno == EAGAIN || \
			 errno == EWOULDBLOCK)
#define TLS_E_SOFT(e)	((e) == GNUTLS_E_INTERRUPTED || (e) == GNUTLS_E_AGAIN)
#define WS_E_SOFT(e)	((e) == WS_E_WANT_READ || (e) == WS_E_WANT_WRITE)
#define WS_E_OP(e)	((e) == WS_E_OP_PING || (e) == WS_E_OP_PONG || \
			 (e) == WS_E_OP_CLOSE)

#define UNUSED(x)	((x) = (x))
#define ARRSZ(a)	(sizeof((a)) / sizeof((a)[0]))
#define STREQ(s1, s2)	(strcmp(s1, s2) == 0)

#define BUFSZ		16384

static int fd_cloexec(int fd)
{
	int flags;
	return ((flags = fcntl(fd, F_GETFD)) < 0 ||
			 fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) ? -1 : 0;
}

static int fd_nonblock(int fd)
{
	int flags;
	return ((flags = fcntl(fd, F_GETFL)) < 0 ||
			fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
				fd_cloexec(fd) < 0) ? -1 : 0;
}

static void closesafe(int fd)
{
	int rc;

	do {
		rc = close(fd);
	} while (rc < 0 && errno == EINTR);
}

static int chld(char *argv[], int fds[2])
{
	sigset_t mask, omask;
	int pipefds[2][2] = { { -1, -1 }, { -1, -1 } };
	int i;

	for (i = 0; i < 2; i++)
		if (pipe(pipefds[i]) < 0)
			goto err0;

	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	switch (fork()) {
	case -1:
		goto err1;
	case  0:
		closesafe(pipefds[0][0]);
		closesafe(pipefds[1][1]);
		dup2(pipefds[1][0], STDIN_FILENO);
		dup2(pipefds[0][1], STDOUT_FILENO);
		closesafe(pipefds[0][1]);
		closesafe(pipefds[1][0]);

		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);
	
		execvp(argv[0], argv);
		err(EXIT_FAILURE, "execvp(): %s", argv[0]);
	}

	sigprocmask(SIG_SETMASK, &omask, NULL);

	fds[0] = pipefds[0][0];
	fds[1] = pipefds[1][1];
	closesafe(pipefds[0][1]);
	closesafe(pipefds[1][0]);

	return 0;
err1:
	sigprocmask(SIG_SETMASK, &omask, NULL);
err0:
	for (i = 0; i < 2; i++) {
		if (pipefds[i][0] != -1)
			closesafe(pipefds[i][0]);
		if (pipefds[i][1] != -1)
			closesafe(pipefds[i][1]);
	}

	return -1;
}

static void rdwr(int fd[2][2])
{
	struct pollfd fds[2];
	unsigned char buf[2][BUFSZ];
	ssize_t n[2] = { 0, 0 }, m[2];
	size_t woff[2];
	int rc, i, j, r, w, s0, s1;

	/* 0 is so called forward path, 1 is backward path. */
	fds[0].fd = fd[0][0];
	fds[0].events = POLLIN;
	fds[1].fd = fd[1][0];
	fds[1].events = POLLIN;

	/* If read and write fds are equal treat them as a socket. */
	s0 = fd[0][0] == fd[0][1];
	s1 = fd[1][0] == fd[1][1];

	while (fds[0].fd != -1 || fds[1].fd != -1) {
		rc = poll(fds, ARRSZ(fds), -1);
		if (rc < 0 && errno == EINTR)
			continue;
		else if (rc < 0)
			err(EXIT_FAILURE, "poll()");
		/* Randomize access to events. */
		i = rand() % 2;
		for (j = 0; j < 2; j++, i++) {
			if (i == 2)
				i = 0;

			r = i == 0 ? fd[0][0] : fd[1][0];
			w = i == 0 ? fd[1][1] : fd[0][1];

			assert(!(fds[i].revents & POLLNVAL));

			if (fds[i].revents & POLLERR)
				goto end;

			if (fds[i].revents & (POLLIN | POLLHUP)) {
				assert(r == fds[i].fd);
				assert(n[i] <= 0);
				woff[i] = 0;
				n[i] = read(r, buf[i], sizeof(buf[i]));
				if (n[i] > 0) {
					/* Stop IN, start OUT. */
					fds[i].fd = w;
					fds[i].events = POLLOUT;
				} else if (n[i] == 0 ||
					   (n[i] < 0 && !UNIX_E_SOFT)) {
					if (n[i] < 0)
						warn("read()");
					else
						warnx("read(): EOF");
					goto end;
				}
				continue;
			}

			if (fds[i].revents & POLLOUT) {
				assert(w == fds[i].fd);
				assert(n[i] > 0);
				while (n[i] > 0) {
					m[i] = write(w, buf[i] + woff[i], n[i]);
					if (m[i] > 0) {
						n[i]    -= m[i];
						woff[i] += m[i];
						/* The buffer is written. */
						if (n[i] == 0) {
							/* Stop OUT, start IN. */
							fds[i].fd = r;
							fds[i].events = POLLIN;
						}
					} else {
						if (UNIX_E_SOFT)
							break;
						warn("write()");
						goto end;
					}
				}
			}

			continue;
end:
			fds[i].fd = -1;
			fds[i].events = 0;
			/* TCP supports half closed connection.
			 * Don't close fd just signal about end of a stream. */
			if (i == 0) {
				s0 ? shutdown(r, SHUT_RD) : closesafe(r);
				s1 ? shutdown(w, SHUT_WR) : closesafe(w);
			} else {
				s1 ? shutdown(r, SHUT_RD) : closesafe(r);
				s0 ? shutdown(w, SHUT_WR) : closesafe(w);
			}
		}
	}

	if (s0)
		closesafe(fd[0][0]);
	if (s1)
		closesafe(fd[1][0]);
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

static ssize_t tlsio(gnutls_transport_ptr_t ptr, void *buf, size_t n,
			ssize_t (*f)(int fd, void *p, size_t n))
{
	int fd = *(int *)ptr;
	ssize_t rc;

	rc = f(fd, buf, n);
	if (rc < 0) {
		if (errno == EINTR)
			return GNUTLS_E_INTERRUPTED;
		else if (errno == EAGAIN || errno == EWOULDBLOCK)
			return GNUTLS_E_AGAIN;
		else
			return -1;
	}

	return rc;
}

static ssize_t tlsi(gnutls_transport_ptr_t ptr, void *buf, size_t n)
{
	return tlsio(ptr, buf, n, read);
}

static ssize_t tlso(gnutls_transport_ptr_t ptr, const void *buf, size_t n)
{
	return tlsio(ptr, (void *)buf, n,
			(ssize_t (*)(int, void *, size_t))write);
}

static void tls_get_int2(gnutls_session_t sess, int *r, int *w)
{
	gnutls_transport_ptr_t p0, p1;

	gnutls_transport_get_ptr2(sess, &p0, &p1);
	*r = *(int *)p0;
	*w = *(int *)p1;
}

static void tls_handshake(gnutls_session_t s)
{
	int rc, r, rfd, wfd;

	tls_get_int2(s, &rfd, &wfd);

	while ((rc = gnutls_handshake(s)) != GNUTLS_E_SUCCESS) {
		if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
			r = !gnutls_record_get_direction(s);
			wait_event(r ? rfd : wfd, r);
		} else {
			errx(EXIT_FAILURE, "gnutls_handshake(): %s",
						gnutls_strerror(rc));
		}
	}
}

static void tls_bye(gnutls_session_t s, gnutls_close_request_t how)
{
	int rc, r, rfd, wfd;

	tls_get_int2(s, &rfd, &wfd);

	while ((rc = gnutls_bye(s, how)) != GNUTLS_E_SUCCESS) {
		if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
			r = !gnutls_record_get_direction(s);
			wait_event(r ? rfd : wfd, r);
		} else {
			warnx("gnutls_bye(): %s", gnutls_strerror(rc));
			break;
		}
	}
}

static void tls(gnutls_session_t s, int fd[2][2])
{
	struct pollfd fds[2];
	unsigned char buf[2][BUFSZ];
	ssize_t n[2] = { 0, 0 }, m[2];
	size_t woff[2], tlsrest;
	int rc, i, j, r, w, timeout, bye;
	char *desc;

	/* [0][0] and [0][1] are for plane data,
	 * [1][0] and [1][1] are for TLS data. */
	gnutls_transport_set_ptr2(s, &fd[1][0], &fd[1][1]);
	gnutls_transport_set_pull_function(s, tlsi);
	gnutls_transport_set_push_function(s, tlso);

	tls_handshake(s);
	desc = gnutls_session_get_desc(s);
       	warnx("Handshake is completed: %s", desc);
	gnutls_free(desc);

	/* 0 is so called forward path, 1 is backward path. */
	fds[0].fd = fd[0][0];
	fds[0].events = POLLIN;
	fds[1].fd = fd[1][0];
	fds[1].events = POLLIN;
	/* These is a copy of rdwr() with adjustments for TLS. */

	bye = 1;
	while (fds[0].fd != -1 || fds[1].fd != -1) {
		/* If we are going to poll TLS for IN event then
		 * check whether TLS state already has bytes to read. */
		if (fds[1].events == POLLIN) {
			tlsrest = gnutls_record_check_pending(s);
			timeout = tlsrest > 0 ? 0 : -1;
		} else {
			tlsrest =  0;
			timeout = -1;
		}

		rc = poll(fds, ARRSZ(fds), timeout);
		if (rc < 0 && errno == EINTR)
			continue;
		else if (rc < 0)
			err(EXIT_FAILURE, "poll()");
		/* Randomize access to events. */
		i = rand() % 2;
		for (j = 0; j < 2; j++, i++) {
			if (i == 2)
				i = 0;

			r = i == 0 ? fd[0][0] : fd[1][0];
			w = i == 0 ? fd[1][1] : fd[0][1];

			assert(!(fds[i].revents & POLLNVAL));

			if (fds[i].revents & POLLERR) {
				if (i == 1)
					bye = 0;
				goto end;
			}

			if (fds[i].revents & (POLLIN | POLLHUP) ||
			    		(i == 1 && tlsrest > 0)) {
				assert(r == fds[i].fd);
				assert(n[i] <= 0);
				woff[i] = 0;

				if (i == 0)
					n[i] = read(r, buf[i], sizeof(buf[i]));
				else
					n[i] = gnutls_record_recv(s, buf[i],
								sizeof(buf[i]));
				if (n[i] > 0) {
					/* Stop IN, start OUT. */
					fds[i].fd = w;
					fds[i].events = POLLOUT;
				} else if (n[i] == 0 ||
					   ((i == 0 && !UNIX_E_SOFT) ||
					    (i == 1 && !TLS_E_SOFT(n[i])))) {
					if (n[i] < 0) i == 0 ?
						warn("read()") :
						warnx("gnutls_record_recv(): %s",
							gnutls_strerror(n[i]));
					else
						warnx("%s: EOF", i == 0 ?
							"read()" : 
							"gnutls_record_recv()");
					goto end;
				}
				continue;
			}

			if (fds[i].revents & POLLOUT) {
				assert(w == fds[i].fd);
				assert(n[i] > 0);
				while (n[i] > 0) {
					if (i == 0)
						m[i] = gnutls_record_send(s,
							buf[i] + woff[i], n[i]);
					else
						m[i] = write(w, buf[i] +
								woff[i], n[i]);
					if (m[i] > 0) {
						n[i]    -= m[i];
						woff[i] += m[i];
						/* The buffer is written. */
						if (n[i] == 0) {
							/* Stop OUT, start IN. */
							fds[i].fd = r;
							fds[i].events = POLLIN;
						}
					} else {
				    		if ((i == 0 && TLS_E_SOFT(m[i])) ||
						    (i == 1 && UNIX_E_SOFT))
							break;
						if (i == 0) {
							warnx("gnutls_record_send(): %s",
								gnutls_strerror(m[i]));
							bye = 0;
						} else {
							warn("write()");
						}
						goto end;
					}
				}
			}

			continue;
end:
			fds[i].fd = -1;
			fds[i].events = 0;
			/* Close read and write sides. */
			closesafe(r);
			if (i == 0 && bye)
				tls_bye(s, GNUTLS_SHUT_WR);
			closesafe(w);
		}
	}
}

static void tls_clt(int fds[2][2], const char *host, int cert)
{
	gnutls_certificate_credentials_t certcred;
	gnutls_anon_client_credentials_t anoncred;
	gnutls_session_t session;

	gnutls_global_init();
	if (cert) {
		gnutls_certificate_allocate_credentials(&certcred);
		gnutls_certificate_set_x509_system_trust(certcred);
	} else {
		gnutls_anon_allocate_client_credentials(&anoncred);
	}

	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_priority_set_direct(session, cert ? "PERFORMANCE" :
						   "PERFORMANCE:+ANON-DH", NULL);

	gnutls_credentials_set(session, cert ? GNUTLS_CRD_CERTIFICATE :
					       GNUTLS_CRD_ANON,
					cert ? (void *)certcred : (void *)anoncred);
	if (host)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS,
						host, strlen(host));
	tls(session, fds);

	gnutls_deinit(session);
	if (cert)
		gnutls_certificate_free_credentials(certcred);
	else
		gnutls_anon_free_client_credentials(anoncred);

	gnutls_global_deinit();
}

static void tls_srv(int fds[2][2])
{
	gnutls_anon_server_credentials_t anoncred;
	gnutls_dh_params_t dh_params;
	gnutls_session_t session;
#define DH_BITS		1024
	gnutls_global_init();
	gnutls_anon_allocate_server_credentials (&anoncred);
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_BITS);
	gnutls_anon_set_server_dh_params(anoncred, dh_params);

	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_priority_set_direct(session, "PERFORMANCE:+ANON-DH", NULL);
	gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);
	gnutls_dh_set_prime_bits(session, DH_BITS);
#undef DH_BITS
	tls(session, fds);

	gnutls_deinit(session);
	gnutls_anon_free_server_credentials(anoncred);
	gnutls_global_deinit();
}

static ssize_t wsio(int fd, void *buf, size_t n,
			ssize_t (*f)(int fd, void *p, size_t n))
{
	ssize_t rc;
	int r = f == read;

	rc = f(fd, buf, n);
	if (rc < 0) {
		if (UNIX_E_SOFT)
			return r ? WS_E_WANT_READ : WS_E_WANT_WRITE;
		else
			return WS_E_IO;
	} else if (rc == 0) {
		return WS_E_EOF;
	}

	return rc;
}

static ssize_t wsi(void *ctx, void *buf, size_t n)
{
	return wsio(((int *)ctx)[0], buf, n, read);
}

static ssize_t wso(void *ctx, const void *buf, size_t n)
{
	return wsio(((int *)ctx)[1], (void *)buf, n,
			(ssize_t (*)(int, void *, size_t))write);
}

#define OP_CLS	0x01
#define OP_PNG	0x02
static void ws(int fd[2][2], const char *host, const char *uri,
			int srv, int bin)
{
	WebSocket ws;
	struct pollfd fds[2];
	unsigned char buf[2][BUFSZ];
	unsigned char ctrl[128];
	ssize_t n[2] = { 0, 0 }, m[2];
	size_t woff[2], uoff = 0, ctrlsz = 0;
	int rc, i, j, r, w, txt, ecode = 0, op = 0;
	ssize_t (*ws_write)(WebSocket *, const void *, size_t);
	int wsinput, timeout;

	/* [0][0] and [0][1] are for plane data, 
	 * [1][0] and [1][1] are for WS data. */
	ws_init(&ws, srv > 0);
	ws_set_bio(&ws, fd[1], wso, wsi);
	ws_write = bin ? ws_bin_write : ws_txt_write;

	while ((rc = ws_handshake(&ws, host, uri, NULL)))
		if (WS_E_SOFT(rc)) {
			r = rc == WS_E_WANT_READ;
			wait_event(r ? fd[1][0] : fd[1][1], r);
		} else {
			errx(EXIT_FAILURE, "ws_handshake() failed -0x%X", -rc);
		}
	warnx("Handshake is completed");

	/* 0 is so called forward path, 1 is backward path. */
	fds[0].fd = fd[0][0];
	fds[0].events = POLLIN;
	fds[1].fd = fd[1][0];
	fds[1].events = POLLIN;
	/* These is a copy of rdwr() with adjustments for WS. */

	while (fds[0].fd != -1 || fds[1].fd != -1) {
		/* If we are going to poll WS for IN event then
		 * check whether WS state already has bytes to read. */
		if (fds[1].events == POLLIN) {
			wsinput = ws_check_pending(&ws);
			timeout = wsinput > 0 ? 0 : -1;
		} else {
			wsinput =  0;
			timeout = -1;
		}

                rc = poll(fds, ARRSZ(fds), timeout);
		if (rc < 0 && errno == EINTR)
			continue;
		else if (rc < 0)
			err(EXIT_FAILURE, "poll()");

		/* Randomize access to events. */
		i = rand() % 2;
		for (j = 0; j < 2; j++, i++) {
			if (i == 2)
				i = 0;

			r = i == 0 ? fd[0][0] : fd[1][0];
			w = i == 0 ? fd[1][1] : fd[0][1];

			assert(!(fds[i].revents & POLLNVAL));

			if (fds[i].revents & POLLERR)
				goto end;

			if (fds[i].revents & (POLLIN | POLLHUP) ||
					(i == 1 && wsinput)) {
				assert(r == fds[i].fd);
				assert(n[i] <= 0);
				woff[i] = 0;

				if (i == 0)
					n[i] = read(r, buf[i] + uoff,
						sizeof(buf[i]) - uoff);
				else
					n[i] = ws_read(&ws, buf[i],
							sizeof(buf[i]), &txt);
				if (n[i] > 0) {
					/* Addin partial UTF8 character. */
					if (i == 0) {
						n[i] += uoff;
						uoff = 0;
					}
					/* Stop IN, start OUT. */
					fds[i].fd = w;
					fds[i].events = POLLOUT;
				} else if (i == 1 && WS_E_OP(n[i])) {
					if (n[i] == WS_E_OP_PONG ||
					    (n[i] == WS_E_OP_PING &&
					     op & OP_PNG))
						goto out;
					if (n[i] == WS_E_OP_PING)
						op |= OP_PNG;
					else if (n[i] == WS_E_OP_CLOSE)
						op |= OP_CLS;
					/* If the forward path is alive
					 * schedule WS_E_OP reply. */
					if (fds[0].fd != -1) {
						fds[0].fd = fd[1][1];
						fds[0].events = POLLOUT;
						fds[0].revents &=
							~(POLLIN | POLLHUP);
						ecode  = ws.ecode;
						ctrlsz = ws.ctrlsz;
						memcpy(ctrl, ws.ctrl, ctrlsz);
					}
					/* Finalize the backward path. */
					if (n[i] == WS_E_OP_CLOSE)
						goto end;
				} else if (n[i] == 0 ||
					    ((i == 0 && !UNIX_E_SOFT) ||
					     (i == 1 && !WS_E_SOFT(n[i])))) {
					if (i == 1 && n[i] == WS_E_EOF)
						n[i] = 0;
					if (n[i] < 0) i == 0 ?
						warn("read()") :
						warnx("ws_read(): failed 0x%zX",
									-n[i]);
					else
						warnx("%sread(): EOF",
							i == 0 ? "" : "ws_");
					goto end;
				}
out:
				continue;
			}

			if (fds[i].revents & POLLOUT) {
				assert(w == fds[i].fd);
				assert(n[i] > 0 || (i == 0 && op > 0));

				while (n[i] > 0) {
					if (i == 0)
						m[i] = ws_write(&ws, buf[i] +
								woff[i], n[i]);
					else
						m[i] = write(w, buf[i] +
								woff[i], n[i]);
					if (m[i] > 0) {
						n[i]    -= m[i];
						woff[i] += m[i];
						/* The buffer is written. */
						if (n[i] == 0) {
							/* Stop OUT, start IN. */
							fds[i].fd = r;
							fds[i].events = POLLIN;
						}
					} else if (i == 0 && 
						   m[i] == WS_E_UTF8_INCOPMLETE) {
						/* Partial UTF8 character. */
						memmove(buf[i], buf[i] +
								woff[i], n[i]);
						uoff = n[i];
						n[i] = 0;
						/* Stop OUT, start IN. */
						fds[i].fd = r;
						fds[i].events = POLLIN;
					} else {
						if ((i == 0 && WS_E_SOFT(m[i])) ||
						    (i == 1 && UNIX_E_SOFT))
							break;
						if (i == 0)
							warnx("ws_write(): "
								"failed 0x%zX",
									-m[i]);
						else
							warn("write()");
					goto end;

					}
				}

				/* WS_E_OP message reply. Check that user
				 * data is drained */
				if (i == 0 && op > 0 && n[0] == 0) {
					if (op & OP_PNG)
						rc = ws_pong(&ws, ctrl, ctrlsz);
					else if (op & OP_CLS)
						rc = ws_close(&ws, ecode, NULL, 0);

					if (rc == 0) {
						if (op & OP_PNG) {
							op &= ~OP_PNG;
						} else if (op & OP_CLS) {
							op &= ~OP_CLS;
							goto end;
						}

						if (op & OP_CLS) {
							fds[i].fd = w;
							fds[i].events = POLLOUT;
						} else {
							fds[i].fd = r;
							fds[i].events = POLLIN;
						}
					} else if (rc == WS_E_WANT_WRITE) {
						fds[i].fd = w;
						fds[i].events = POLLOUT;
					} else if (rc < 0) {
						warnx("ws_%s(): failed -0x%X",
							op & OP_PNG ?
							    "pong" : "close",
								-rc);
						/* Finalize the forward path. */
						goto end;
					}
				}
			}

			continue;
end:
			fds[i].fd = -1;
			fds[i].events = 0;
			/* Close read and write sides. */
			closesafe(r);
			closesafe(w);
		}
	}

	ws_deinit(&ws);
}
#undef OP_CLS
#undef OP_PNG

static void sigchld(int signo)
{
	UNUSED(signo);
	while (waitpid(-1, NULL, WNOHANG) > 0) ;
}

static void revfd(int fds[2][2])
{
	int fd, i;

	for (i = 0; i < 2; i++) {
		fd = fds[0][i];
		fds[0][i] = fds[1][i];
		fds[1][i] = fd;
	}
}

static int srv_loop(int fd)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int afd, q = 0;

	while (!q) {
		slen = sizeof(ss);
		do {
			afd = accept(fd, (struct sockaddr *)&ss, &slen);
		} while (afd < 0 && errno == EINTR);

		if (afd < 0) {
			warn("accept()");
			continue;
		}

		switch (fork()) {
		case 0:
			q = 1;
			break;	
		default:
			closesafe(afd);
			break;
		}
	}
	/* child */
	closesafe(fd);
	return afd;
}

static int srv_once(int fd)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int afd;

	do {
		afd = accept(fd, (struct sockaddr *)&ss, &slen);
	} while (afd < 0 && errno == EINTR);

	if (afd < 0)
		err(EXIT_FAILURE, "accept()");

	closesafe(fd);
	return afd;
}

static int inet_fd(const char *addr, const char *port,
			int fds[2], int srv, int keep)
{
	int fd;

	fd = srv ? tcp_listen(addr, port) :
		   tcp_connect(addr, port, 0);
	if (fd < 0)
		err(EXIT_FAILURE, "tcp_%s()", srv ? "listen" : "connect");

	fds[0] = fds[1] = !srv ? fd :
			  keep ? srv_loop(fd) : srv_once(fd);
	return 0;
}

#define WS	0x01
#define TLS	0x02
#define INET	0x04
#define RDWR	0x08
int main(int argc, char *argv[])
{
	extern const char *const __progname;
	int opt, rev = 0, bin = 0, srv = 0, cert = 0, keep = 0;
	char *host = NULL, *uri = NULL, *optstr;
	int prog = STREQ(__progname, "ws")   ? WS  :
		   STREQ(__progname, "tls")  ? TLS :
		   STREQ(__progname, "inet") ? INET : RDWR;

	int fds[2][2] = {
		{ STDIN_FILENO, STDOUT_FILENO },
		{ -1 , -1 }, 
	};

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, sigchld);
	srand(time(NULL));

	optstr = prog & WS   ? "brsh:u:" :
		 prog & TLS  ? "crsh:"   :
		 prog & INET ? "krs"     : "";

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
#define OPT_BOOL(o, v)  case o: v = 1; break;
#define OPT_STR(o, v)  case o: v = optarg; break;
		OPT_BOOL('r', rev)
		OPT_BOOL('b', bin)
		OPT_BOOL('s', srv)
		OPT_STR ('u', uri)
		OPT_STR ('h', host)
		OPT_BOOL('c', cert)
		OPT_BOOL('k', keep)
#undef OPT_STR
#undef OPT_BOOL
		default: exit(EXIT_FAILURE);
		}
	}

	argv += optind;
	argc -= optind;

	if ((prog & INET && argc < 2 + rev) || argc < 1)
		errx(EXIT_FAILURE, "not enough arguments");

	if (prog & WS) {
		if (host == NULL || uri == NULL)
			errx(EXIT_FAILURE, "%s option is not provided",
					host == NULL ? "host" : "uri");
	}

	if (prog & INET) {
		inet_fd(argv[0], argv[1], fds[1], srv, keep);
		/* For inet in case of reverse option replace
		 * STDIN/STDOUT with child process fds. */
		if (rev && chld(argv + 2, fds[0]) < 0)
			errx(EXIT_FAILURE, "can not run child");
	} else if (chld(argv, fds[1]) < 0) {
		errx(EXIT_FAILURE, "can not run child");
	}

	if (fd_nonblock(fds[0][0]) < 0 ||
	    fd_nonblock(fds[0][1]) < 0 ||
	    fd_nonblock(fds[1][0]) < 0 ||
	    fd_nonblock(fds[1][1]) < 0)
		errx(EXIT_FAILURE, "fd_nonblock() failed");

	if (rev)
		revfd(fds);

	prog & WS   ?  ws(fds, host, uri, srv, bin) :
	prog & TLS  ? (srv ? tls_srv(fds) : tls_clt(fds, host, cert)) :
	prog & INET ?  rdwr(fds) : rdwr(fds);

#define S(s) s, sizeof(s)-1
	write(STDERR_FILENO, S("END\n"));
#undef S
	return EXIT_SUCCESS;
}
#undef WS
#undef TLS
#undef INET
#undef RDWR

