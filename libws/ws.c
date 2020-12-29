#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include "ws.h"
#include "sha1.h"
#include "base64.h"

#define OP_CONT			0x00
#define OP_TEXT			0x01
#define OP_BIN			0x02
/* 0x03 - 0x07 reserved */
#define OP_CLOSE		0x08
#define OP_PING			0x09
#define OP_PONG			0x0A
/* 0x0B - 0x0F reserved */

#define CTRL(op)		(((op) >> 3) & 0x01)
#define DATA(op)		((op) != OP_CONT && !CTRL((op)))
#define CONT(op)		((op) == OP_CONT)

#define GUID			"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WS_H_BUF_SIZE		8192

#define HDR_HOST		0x01
#define HDR_UPGRADE		0x02
#define HDR_SEC_KEY		0x04
#define HDR_SEC_ACCEPT		0x08
#define HDR_REQ_ALL		(HDR_HOST | HDR_UPGRADE | HDR_SEC_KEY)
#define HDR_RES_ALL		(HDR_UPGRADE | HDR_SEC_ACCEPT)

#define STREQI(s1, s2)		(strcasecmp(s1, s2) == 0)
#define STREQ(s1, s2)		(strcmp(s1, s2) == 0)

#define WS_H_BUF(ws)		((ws)->h_buf + (ws)->h_off)
#define WS_H_BUF_LEN(ws)	(WS_H_BUF_SIZE - (ws)->h_off)

#define WS_I_BUF(ws)		((ws)->i_buf + (ws)->i_off)
#define WS_I_BUF_LEN(ws)	(WS_IO_BUF_SIZE - (ws)->i_off)
#define WS_O_BUF(ws)		((ws)->o_buf + (ws)->o_off)
#define WS_O_BUF_LEN(ws)	(WS_IO_BUF_SIZE - (ws)->o_off)

#define ARRSZ(a)		(sizeof((a)) / sizeof((a)[0]))

#define HTTP_SW			0
#define HTTP_BAD		1
#define HTTP_NFOUND		2
#define HTTP_ERR		3
#define CRLFx2			"\r\n\r\n"
#define CRLF			"\r\n"

enum {
	STATE_H_INIT,
	STATE_H_MSG_RD,
	STATE_H_MSG_WR,
	STATE_H_REQ,
	STATE_H_RES
};

enum {
	STATE_I_HDR,
	STATE_I_PLEN16,
	STATE_I_PLEN64,
	STATE_I_MASK,
	STATE_I_PAYLOAD0,
	STATE_I_PAYLOAD,
	STATE_I_CTRL,
	STATE_I_DRAIN
};

enum {
	STATE_O_HDR,
	STATE_O_PAYLOAD,
	STATE_O_DRAIN
};

struct http_hdr {
	const char	*name;
	const char	*value;
};

union ws_arg {
	struct {
		void (*hnd)(void *opaque, const void *buf, size_t n, int txt);
		void *opaque;
	} h;
	struct {
		void	*buf;
		size_t	n;
		int	*txt;
	} r;
};

struct ws_hand {
	const char	*uri;
	const char	*host;
	unsigned int	hdrs;
	char		*sec;
};

static const char *http_status_msg[] = {
	"101 Switching Protocols",
	"400 Bad Request",
	"404 Not Found",
	"500 Internal Server Error"
};

static char *skip_space(const char *p)
{
	while (isspace(*p))
		++p;
	return (char *)p;
}

static int http_req_line(char **cur, char **method, char **uri, int *ver)
{
	char *p = *cur;

	/* method /xxx/zzz HTTP/1.X\r\n */
	*strstr(p, CRLF) = 0;
	*method = p;
	if ((p = strchr(p, ' ')) == NULL)
		return -1;

	*p++ = 0;
	p = *uri = skip_space(p);

	p = strchr(p, ' ');
	if (!p)
		return -1;
	*p++ = 0;
	p = skip_space(p);

	/* HTTP/1.X */
	if (strncmp(p, "HTTP/1.", 7))
		return -1;
	p += 7;
	if (*p != '0' && *p != '1')
		return -1;
	*ver = *p++ == '0' ? 0 : 1;
	if (*p != 0)
		return -1;
	/* CRLF */
	p += 2;
	*cur = p;
	return 0;
}

static int http_res_line(char **cur, int *ver, int *code, char **reason)
{
	char *p = *cur;

	/* HTTP/1.X code[ reason]\r\n */
	*strstr(p, CRLF) = 0;

	/* HTTP/1.X */
	if (strncmp(p, "HTTP/1.", 7))
		return -1;
	p += 7;
	if (*p != '0' && *p != '1')
		return -1;
	*ver = *p++ == '0' ? 0 : 1;

	if (*p != ' ')
		return -1;

	p = skip_space(p);

	if (!isdigit(p[0]) || !isdigit(p[1]) ||
	    !isdigit(p[2]) || (p[3] != ' ' && p[3] != 0))
		return -1;

	*code = atoi(p);
	if (*code <= 0)
		return -1;

	p += 3;
	p = skip_space(p);

	*reason = p;
	p += strlen(p);
	assert(*p == 0);
	/* CRLF */
	p += 2;
	*cur = p;
	return 0;
}

static ssize_t http_msg(WebSocket *ws, const struct http_hdr *hdrs,
				int nhdrs, const char *uhdrs)
{
	int rc, i;

	for (i = 0; i < nhdrs; i++) {
		rc = snprintf((char *)WS_H_BUF(ws), WS_H_BUF_LEN(ws),
				"%s: %s" CRLF,
				hdrs[i].name, hdrs[i].value);
		if (rc < 0 || rc >= (int)WS_H_BUF_LEN(ws))
			return -1;
		ws->h_off += rc;
	}

	if (uhdrs) {
		rc = snprintf((char *)WS_H_BUF(ws), WS_H_BUF_LEN(ws),
					"%s", uhdrs);
		if (rc < 0 || rc >= (int)WS_H_BUF_LEN(ws))
			return -1;
		ws->h_off += rc;
	}

	rc = snprintf((char *)WS_H_BUF(ws), WS_H_BUF_LEN(ws), CRLF);
	if (rc < 0 || rc >= (int)WS_H_BUF_LEN(ws))
		return -1;
	ws->h_off += rc;

	return 0;
}

static ssize_t
http_msg_res(WebSocket *ws, int status, int ver,
		const struct http_hdr *hdrs, int nhdrs, const char *uhdrs)
{
	int rc;

	assert(ws->h_off == 0);

	if (status > (int)ARRSZ(http_status_msg))
		return -1;

	rc = snprintf((char *)ws->h_buf, WS_H_BUF_SIZE,
			"HTTP/1.%d %s" CRLF,
			ver, http_status_msg[status]);
	if (rc < 0 || rc >= (int)WS_H_BUF_LEN(ws))
		return -1;

	ws->h_off += rc;

	return http_msg(ws, hdrs, nhdrs, uhdrs);
}

static ssize_t
http_msg_req(WebSocket *ws, const char *method, const char *path, int ver,
		const struct http_hdr *hdrs, int nhdrs, const char *uhdrs)
{
	int rc;

	assert(ws->h_off == 0);

	rc = snprintf((char *)ws->h_buf, WS_H_BUF_SIZE,
			"%s %s HTTP/1.%d" CRLF, method, path, ver);
	if (rc < 0 || rc >= (int)WS_H_BUF_LEN(ws))
		return -1;

	ws->h_off += rc;

	return http_msg(ws, hdrs, nhdrs, uhdrs);
}

static int http_msg_collect(WebSocket *ws)
{
	ssize_t n;
	char *p;

	for (;;) {
		n = ws->recv(ws->ctx, WS_H_BUF(ws), WS_H_BUF_LEN(ws)-1);
		if (n <= 0)
			return n == 0 ? WS_E_EOF : n;

		ws->h_off += n;
		ws->h_buf[ws->h_off] = 0;
		/* Find the end of http header. */
		p = strstr((char *)ws->h_buf, CRLFx2);
		if (p) {
			*(p + 2) = 0;
			ws->h_data = (unsigned char *)p + 4;
			break;
		}
		/* The buffer is full and there is no CRLFx2. */
		if (WS_H_BUF_LEN(ws)-1 == 0)
			return WS_E_HANDSHAKE;
	}

	return 0;
}

static void trim(char *p)
{
	size_t n = strlen(p);

	while (n > 0 && isspace(p[n-1]))
		p[--n] = 0;
}

static int
http_msg_hdr(char **cur, void *opaque,
	     int (*on_hdr)(const char *name, const char *value,
				void *opaque))
{
	char *p = *cur, *q, *name, *value;
	int rc;

	while ((q = strstr(p, CRLF)) != NULL) {
		*q = 0;
		name = skip_space(p);
		if ((p = strchr(name, ':')) == NULL)
			return WS_E_HTTP_HDR;

		*p++ = 0;
		value = skip_space(p);
		trim(value);
		p = q + 2;
		if (on_hdr && (rc = on_hdr(name, value, opaque)) < 0)
			return WS_E_HTTP_HDR;
	}

	*cur = p;
	return 0;
}

static int sec_accept_calc(const char *key, char *buf, size_t n)
{
	unsigned char sha1[20];
	size_t olen;
	int m;

	/* Concat Sec-WebSocket-Key and GUID, calculate sha1, convert the
	 * result to base64. */
	m = snprintf(buf, n, "%s%s", key, GUID);
	if (m < 0 || m >= (int)n)
		return -1;
	if (sha1sum((unsigned char *)buf, m, sha1) < 0)
		return -1;
	if (base64encode((unsigned char *)buf, n,
				&olen, sha1, ARRSZ(sha1)) < 0)
		return -1;

	return 0;
}

static int sec_accept_check(const char *accept, const char *key)
{
	char buf[1024];

	if (sec_accept_calc(key, buf, sizeof(buf)) < 0)
		return -1;

	if (!STREQ(accept, buf))
		return -1;

	return 0;
}

static int on_req(const char *method, const char *uri, int ver, void *opaque)
{
	struct ws_hand *hand = opaque;

	if (!STREQI(method, "GET") || ver != 1)
		return WS_E_HTTP_REQ_LINE;
	if (!STREQI(hand->uri, uri))
		return WS_E_HTTP_REQ_URI;

	return 0;
}

static int on_req_hdr(const char *name, const char *value, void *opaque)
{
	struct ws_hand *hand = opaque;
	int rc = WS_E_HTTP_HDR;

	if (STREQI(name, "Host")) {
		if (hand->hdrs & HDR_HOST)
			return rc;
		if (!STREQI(value, hand->host))
			return rc;
		hand->hdrs |= HDR_HOST;
	} else if (STREQI(name, "Upgrade")) {
		if (!STREQI(value, "websocket"))
			return rc;
		hand->hdrs |= HDR_UPGRADE;
	} else if (STREQI(name, "Sec-WebSocket-Key")) {
		if (hand->hdrs & HDR_SEC_KEY)
			return rc;
		hand->sec = strdup(value);
		if (hand->sec == NULL)
			return rc;
		hand->hdrs |= HDR_SEC_KEY;
	} else if (STREQI(name, "Sec-WebSocket-Version")) {
		if (!STREQ(value, "13"))
			return rc;
	}

	return 0;
}

static int
http_req(WebSocket *ws, void *opaque,
	 int (*on_req)(const char *, const char *, int, void *),
	 int (*on_hdr)(const char *, const char *, void *))
{
	char *p, *uri, *method;
	int rc, ver;

	p = (char *)ws->h_buf;

	rc = http_req_line(&p, &method, &uri, &ver);
	if (rc < 0)
		return WS_E_HTTP_REQ_LINE;

	rc = on_req(method, uri, ver, opaque);
	if (rc < 0)
		return rc;

	rc = http_msg_hdr(&p, opaque, on_hdr);
	if (rc < 0)
		return rc;

	return 0;
}

static int
srv_req(WebSocket *ws, const char *host, const char *uri, const char *uhdrs)
{
	struct ws_hand hand;
	char buf[1024];
	int rc, status;
	struct http_hdr hdrs[] = {
		{ "Connection",		 "keep-alive, Upgrade" },
		{ "Upgrade",		 "websocket" },
		{ "Sec-WebSocket-Accept", buf }
	};

	memset(&hand, 0, sizeof(hand));

	hand.host = host;
	hand.uri  = uri;

	rc = http_req(ws, &hand, on_req, on_req_hdr);
	if (rc < 0 || (rc == 0 && hand.hdrs != HDR_REQ_ALL)) {
		status = HTTP_BAD;
		if (rc == WS_E_HTTP_REQ_URI)
			status = HTTP_NFOUND;
		else if (!rc)
			rc = WS_E_HANDSHAKE;
		goto out;
	}

	if (sec_accept_calc(hand.sec, buf, sizeof(buf)) == 0) {
		status = HTTP_SW;
		rc = 0;
	} else {
		status = HTTP_ERR;
		rc = WS_E_HANDSHAKE;
	}
out:
	free(hand.sec);

	if (http_msg_res(ws, status, 1,
			status == HTTP_SW ? hdrs : NULL,
			status == HTTP_SW ? ARRSZ(hdrs) : 0, uhdrs) < 0)
		return WS_E_HANDSHAKE;

	ws->err = rc;
	return 0;
}

static int on_res(int ver, int code, const char *reason, void *opaque)
{
	(void)opaque;
	(void)reason;
	return (ver != 1 || code != 101) ? WS_E_HTTP_RES_LINE : 0;
}

static int on_res_hdr(const char *name, const char *value, void *opaque)
{
	struct ws_hand *hand = opaque;
	int rc = WS_E_HTTP_RES_LINE;

	if (STREQI(name, "Upgrade")) {
		if (!STREQI(value, "websocket"))
			return rc;
		hand->hdrs |= HDR_UPGRADE;
	} else if (STREQI(name, "Sec-WebSocket-Accept")) {
		if (hand->hdrs & HDR_SEC_ACCEPT)
			return rc;
		if (sec_accept_check(value, hand->sec) < 0)
			return rc;
		hand->hdrs |= HDR_SEC_ACCEPT;
	}

	return 0;
}

static int
http_res(WebSocket *ws, void *opaque,
	 int (*on_res)(int ver, int code, const char *reason, void *opaque),
	 int (*on_hdr)(const char *name, const char *value, void *opaque))
{
	int rc, ver, code;
	char *p, *reason;

	p = (char *)ws->h_buf;

	rc = http_res_line(&p, &ver, &code, &reason);
	if (rc < 0)
		return WS_E_HTTP_RES_LINE;

	rc = on_res(ver, code, reason, opaque);
	if (rc < 0)
		return rc;

	rc = http_msg_hdr(&p, opaque, on_hdr);
	if (rc < 0)
		return rc;

	return 0;
}

static int usr_res(WebSocket *ws)
{
	struct ws_hand hand;
	int rc;

	memset(&hand, 0, sizeof(hand));
	hand.sec = ws->sec;

	rc = http_res(ws, &hand, on_res, on_res_hdr);
	if (rc == 0 && hand.hdrs != HDR_RES_ALL)
		rc = WS_E_HANDSHAKE;

	return rc;
}

static int srv_handshake(WebSocket *ws, const char *host,
					const char *uri, const char *uhdrs)
{
	int rc = 0, q = 0;
	ssize_t n;

	while (!q) {
		switch (ws->h_state) {
		case STATE_H_INIT:
			ws->h_state = STATE_H_MSG_RD;
			/* THROUGH */
		case STATE_H_MSG_RD:
			rc = http_msg_collect(ws);
			if (rc < 0)
				return rc;
			if (ws->h_data != WS_H_BUF(ws))
				return WS_E_HTTP_EXTRA_DATA;
			ws->h_state = STATE_H_REQ;
			ws->h_off = 0;
			/* THROUGH */
		case STATE_H_REQ:
			rc = srv_req(ws, host, uri, uhdrs);
			if (rc < 0)
				return rc;
			ws->h_state = STATE_H_MSG_WR;
			ws->h_data = ws->h_buf;
			ws->h_left = ws->h_off;
			ws->h_off = 0;
			/* THROUGH */
		case STATE_H_MSG_WR:
			n = ws->send(ws->ctx, ws->h_data, ws->h_left);
			if (n < 0)
				return n;
			ws->h_data += n;
			ws->h_left -= n;
			if (!ws->h_left) {
				rc = ws->err;
				q = 1;
			}
			break;
		default:
			abort();
		}
	}

	return rc;
}

static int usr_handshake(WebSocket *ws, const char *host,
					const char *uri, const char *uhdrs)
{
	int rc = 0, q = 0;
	ssize_t n;
	struct http_hdr hdrs[] = {
		{ "Upgrade",		   "websocket" },
		{ "Connection",		   "keep-alive, Upgrade" },
		{ "Host",		   host },
		{ "Sec-WebSocket-Key",	   ws->sec },
		{ "Sec-WebSocket-Version", "13" }
	};

	while (!q) {
		switch (ws->h_state) {
		case STATE_H_INIT:
			rc = http_msg_req(ws, "GET", uri, 1,
						hdrs, ARRSZ(hdrs), uhdrs);
			if (rc < 0)
				return WS_E_HANDSHAKE;
			ws->h_state = STATE_H_MSG_WR;
			ws->h_data = ws->h_buf;
			ws->h_left = ws->h_off;
			ws->h_off = 0;
			/* THROUGH */
		case STATE_H_MSG_WR:
			n = ws->send(ws->ctx, ws->h_data, ws->h_left);
			if (n < 0)
				return n;
			ws->h_data += n;
			ws->h_left -= n;
			if (ws->h_left > 0)
				break;
			ws->h_state = STATE_H_MSG_RD;
			/* THROUGH */
		case STATE_H_MSG_RD:
			rc = http_msg_collect(ws);
			if (rc < 0)
				return rc;
			ws->h_state = STATE_H_RES;
			/* THROUGH */
		case STATE_H_RES:
			rc = usr_res(ws);
			if (rc < 0)
				return rc;
			if (ws->h_data != WS_H_BUF(ws)) {
				ws->h_left = WS_H_BUF(ws) - ws->h_data;
				memmove(ws->h_buf, ws->h_data, ws->h_left);
			}
			ws->h_off = 0;
			q = 1;
			break;
		default:
			abort();
		}
	}

	return rc;
}

int ws_check_pending(const WebSocket *ws)
{
	return ws->i_state == STATE_I_DRAIN || ws->h_left > 0;
}

int ws_handshake(WebSocket *ws, const char *host,
				const char *uri, const char *uhdrs)
{
	return (ws->srv ? srv_handshake : usr_handshake)(ws, host, uri, uhdrs);
}

static uint16_t get_u16(uint8_t *p)
{
	return (p[0] << 8) | p[1];
}

static uint64_t get_u64(uint8_t *p)
{
	return  ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
		((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
	        (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
}

static void put_u16(uint8_t *p, uint16_t n)
{
	p[0] = (n >> 8) & 0xFF;
	p[1] =  n       & 0xFF;
}

static void put_u64(uint8_t *p, uint64_t n)
{
	p[0] = (n >> 56) & 0xFF;
	p[1] = (n >> 48) & 0xFF;
	p[2] = (n >> 40) & 0xFF;
	p[3] = (n >> 32) & 0xFF;
	p[4] = (n >> 24) & 0xFF;
	p[5] = (n >> 16) & 0xFF;
	p[6] = (n >>  8) & 0xFF;
	p[7] =  n        & 0xFF;
}

static int check_op(unsigned char op)
{
	/* drop control bit. */
	return (op & 0x07) < 3;
}

int ws_init(WebSocket *ws, int srv)
{
	unsigned char blah[16];
	unsigned char *p;
	size_t olen = 0;
	int i;

	memset(ws, 0, sizeof(*ws));

	ws->h_buf = calloc(1, WS_H_BUF_SIZE);
	if (ws->h_buf == NULL)
		return -1;

	p = calloc(1, 2 * WS_IO_BUF_SIZE);
	if (p == NULL) {
		free(ws->h_buf);
		return -1;
	}

	ws->srv = srv;
	ws->i_buf = p;
	ws->o_buf = p + WS_IO_BUF_SIZE;
	ws->utf8_on = 1;

	if (!srv) {
		for (i = 0; i < (int)ARRSZ(blah); i++)
			blah[i] = rand() % 256;
		if (base64encode(WS_O_BUF(ws), WS_O_BUF_LEN(ws), &olen,
						blah, ARRSZ(blah)) < 0) {
			free(p);
			free(ws->h_buf);
			return -1;
		}
		ws->sec = (char *)WS_O_BUF(ws);
	}

	return 0;
}

void ws_deinit(WebSocket *ws)
{
	free(ws->h_buf);
	free(ws->i_buf);
	memset(ws, 0, sizeof(*ws));
}

void ws_set_bio(WebSocket *ws, void *ctx,
		 ssize_t (*send)(void *ctx, const void *buf, size_t n),
		 ssize_t (*recv)(void *ctx, void *buf, size_t n))
{
	ws->ctx  = ctx;
	ws->send = send;
	ws->recv = recv;
}

#define EQUAL(n, m)	((n) == (m))
#define RANGE(n, l, h)	((n) >= (l) && (n) <= (h))
#define TAIL(n)		RANGE(n, 0x80, 0xBF)

static int utf8(unsigned char *ptr, unsigned char **end, size_t n)
{
	int m;

	if (RANGE(ptr[0], 0x00, 0x7F)) {
		m = 1;
	} else if (RANGE(ptr[0], 0xC2, 0xDF)) {
		if (n < 2)
			return 2 - n;
		if (!TAIL(ptr[1]))
			return -1;
		m = 2;
	} else if (RANGE(ptr[0], 0xE0, 0xEF)) {
		if (n < 2)
			return 3 - n;
		if ((EQUAL(ptr[0], 0xE0) && !RANGE(ptr[1], 0xA0, 0xBF)) ||
		    (RANGE(ptr[0], 0xE1, 0xEC) && !TAIL(ptr[1]))   ||
		    (EQUAL(ptr[0], 0xED) && !RANGE(ptr[1], 0x80, 0x9F)) ||
		    (RANGE(ptr[0], 0xEE, 0xEF) && !TAIL(ptr[1])))
			return -1;
		if (n < 3)
			return 3 - n;
		if (!TAIL(ptr[2]))
			return -1;
		m = 3;
	} else if (RANGE(ptr[0], 0xF0, 0xF4)) {
		if (n < 2)
			return 4 - n;
		if ((EQUAL(ptr[0], 0xF0) && !RANGE(ptr[1], 0x90, 0xBF)) ||
		    (RANGE(ptr[0], 0xF1, 0xF3) && !TAIL(ptr[1]))   ||
		    (EQUAL(ptr[0], 0xF4) && !RANGE(ptr[1], 0x80, 0x8F)))
			return -1;
		if (n < 3)
			return 4 - n;
		if (!TAIL(ptr[2]))
			return -1;
		if (n < 4)
			return 4 - n;
		if (!TAIL(ptr[3]))
			return -1;
		m = 4;
	} else {
		return -1;
	}

	if (end)
		*end = ptr + m;

	return 0;
}
#undef TAIL
#undef RANGE
#undef EQUAL

static ssize_t utf8len(const unsigned char *buf, size_t n)
{
	unsigned char *p, *e;
	ssize_t m;

	assert(n > 0);
	p = (unsigned char *)buf;
	e = p + n;

	while (p < e) {
		m = utf8(p, &p, e - p);
		if (m < 0)
			return m;
		else if (m > 0)
			break;
	}

	return p - buf;
}

static ssize_t
ws_write(WebSocket *ws, unsigned char op, const void *buf, size_t n)
{
	unsigned char len, *p, q = 0;
	size_t i;
	int rc;

	while (!q) {
		switch (ws->o_state) {
		case STATE_O_HDR:
			p = ws->o_buf;

			len = (n < 126) ? n : (n < 0x10000) ? 126 : 127;
			*p++ = 0x80 | op;
			*p++ = (ws->srv ? 0x00 : 0x80) | len;

			if (len == 126) {
				put_u16(p, n);
				p += 2;
			} else if (len == 127) {
				put_u64(p, n);
				p += 8;
			}

			if (!ws->srv)
				for (i = 0; i < 4; i++)
					*p++ = ws->o_mskbuf[i] = rand() % 256;

			ws->o_off = p - ws->o_buf;
			ws->o_imsk = 0;
			ws->o_offall = 0;
			ws->o_lenall = n;
			ws->o_state = STATE_O_PAYLOAD;
			/* THROUGH */
		case STATE_O_PAYLOAD:
			assert(WS_O_BUF_LEN(ws) > 0);
			assert(ws->o_lenall > 0);
			ws->o_len = ws->o_lenall > WS_O_BUF_LEN(ws) ?
					WS_O_BUF_LEN(ws) : ws->o_lenall;
			memcpy(WS_O_BUF(ws), buf + ws->o_offall, ws->o_len);

			if (!ws->srv) {
				p = WS_O_BUF(ws);
				for (i = 0; i < ws->o_len; i++)
					p[i] ^= ws->o_mskbuf[ws->o_imsk++ % 4];
			}

			ws->o_off += ws->o_len;
			ws->o_data = ws->o_buf;
			ws->o_left = ws->o_off;
			ws->o_state = STATE_O_DRAIN;
			/* THROUGH */
		case STATE_O_DRAIN:
			rc = ws->send(ws->ctx, ws->o_data, ws->o_left);
			if (rc < 0)
				return rc;

			ws->o_data += rc;
			ws->o_left -= rc;
			if (ws->o_left > 0)
				break;
			/* The current chunk is sent. */
			ws->o_offall += ws->o_len;
			ws->o_lenall -= ws->o_len;
			if (ws->o_lenall > 0) {
				ws->o_state = STATE_O_PAYLOAD;
				ws->o_off = 0;
			} else {
				ws->o_state = STATE_O_HDR;
				q = 1;
			}
			break;
		default:
			abort();
		}
	}

	return n;
}

ssize_t ws_txt_write(WebSocket *ws, const void *buf, size_t n)
{
	ssize_t	rc;

	if (!n)
		return 0;

	if (ws->utf8_on) {
		rc = utf8len(buf, n);
		if (rc <= 0)
			return rc == 0 ? WS_E_UTF8_INCOPMLETE : WS_E_NON_UTF8;
		n = rc;
	}

	return ws_write(ws, OP_TEXT, buf, n);
}

ssize_t ws_bin_write(WebSocket *ws, const void *buf, size_t n)
{
	if (!n)
		return 0;
	return ws_write(ws, OP_BIN, buf, n);
}

int ws_ping(WebSocket *ws, const void *buf, size_t n)
{
	ssize_t rc;

	if (n > 125)
		return WS_E_TOO_LONG;

	return (rc = ws_write(ws, OP_PING, buf, n)) < 0 ? rc : 0;
}

int ws_pong(WebSocket *ws, const void *buf, size_t n)
{
	ssize_t rc;

	if (n > 125)
		return WS_E_TOO_LONG;

	return (rc = ws_write(ws, OP_PONG, buf, n)) < 0 ? rc : 0;
}

int ws_close(WebSocket *ws, uint16_t ecode, const void *msg, size_t n)
{
	ssize_t rc;
	unsigned char buf[125];

	if (n > 123)
		return WS_E_TOO_LONG;

	put_u16(buf, ecode);
	if (n > 0) {
		if (ws->utf8_on) {
			rc = utf8len(msg, n);
			if (rc <= 0 || (size_t)rc != n)
				return WS_E_NON_UTF8;
		}
		memcpy(buf + 2, msg, n);
	}

	return (rc = ws_write(ws, OP_CLOSE, buf, n + 2)) < 0 ? rc : 0;
}

static ssize_t read_n(WebSocket *ws, unsigned char *buf, size_t n)
{
	size_t len = 0;
	ssize_t m;
	/* Handshake buffer may contain some frames, first consume
	 * this buffer then do real read. */
	if (ws->h_left > 0) {
		m = ws->h_left > n ? n : ws->h_left;
		memcpy(buf, ws->h_buf + ws->h_off, m);

		ws->h_left -= m;
		ws->h_off  += m;
		if (ws->h_left == 0) {
			ws->h_off = 0;
			free(ws->h_buf);
			ws->h_buf = NULL;
		}

		buf += m;
		n   -= m;
		len += m;
		if (n == 0)
			return len;
	}

	m = ws->recv(ws->ctx, buf, n);
	if (m <= 0)
		return m == 0 ? WS_E_EOF : m;
	len += m;

	return len;
}

static ssize_t tbuf_read(WebSocket *ws, size_t n)
{
	ssize_t rc;

	rc = read_n(ws, ws->t_buf + ws->t_off, n);
	if (rc < 0)
		return rc;
	ws->t_off += rc;

	return rc;
}

static ssize_t ws_handler(WebSocket *ws, union ws_arg *arg, int hnd)
{
	unsigned char b0, b1, fin, msk, op;
	unsigned char *p;
	size_t len, i, n;
	uint64_t m;
	ssize_t rc;

	for (;;) {
		switch (ws->i_state) {
		case STATE_I_HDR:
			rc = tbuf_read(ws, 2 - ws->t_off);
			if (rc < 0)
				return rc;
			if (ws->t_off < 2)
				continue;
			ws->t_off = 0;

			b0 = ws->t_buf[0];
			b1 = ws->t_buf[1];

			fin  = (b0 >> 7) & 0x01;
			op   =  b0       & 0x0F;
			/* Unexpected opcode. */
			if (!check_op(op))
				return WS_E_BAD_OPCODE;
			/* Control frame can't be fragmented. */
			if (CTRL(op) && !fin)
				return WS_E_FAULT_FRAME;
			/* Continuation frame is not expected. */
			if (CONT(op) && !ws->cont)
				return WS_E_FAULT_FRAME;
			/* Expect continuation but got a data frame. */
			if (ws->cont && DATA(op))
				return WS_E_FAULT_FRAME;

			msk = (b1 >>  7) & 0x01;
			len =  b1        & 0x7F;
			if (ws->srv && !msk)
				return WS_E_EXPECT_MASK;
			if (!ws->srv && msk)
				return WS_E_UNEXPECTED_MASK;
			/* Control frame is to long. */
			if (CTRL(op) && len > 125)
				return WS_E_BAD_LEN;
			if (DATA(op) && len == 0)
				return WS_E_BAD_LEN;
			if (op == OP_CLOSE && len < 2)
				return WS_E_FAULT_FRAME;

			/* If the frame is not finished store the opcode. */
			if (!fin && DATA(op))
				ws->cont = op;

			if (CONT(op)) {
				op = ws->cont;
				/* The last continuation frame. */
				if (fin)
					ws->cont = 0;
			}

			ws->op = op;
			ws->i_len = len < 126 ? len : 0;
			ws->i_state = len == 126 ? STATE_I_PLEN16 :
				      len == 127 ? STATE_I_PLEN64 :
				(ws->srv ? STATE_I_MASK :
				  ws->i_len == 0 ? STATE_I_CTRL : STATE_I_PAYLOAD0);
			break;
		case STATE_I_MASK:
			rc = tbuf_read(ws, 4 - ws->t_off);
			if (rc < 0)
				return rc;
			if (ws->t_off < 4)
				continue;
			ws->t_off = 0;

			memcpy(ws->i_mskbuf, ws->t_buf, 4);
			ws->i_imsk = 0;
			ws->i_state = ws->i_len == 0 ?
					STATE_I_CTRL : STATE_I_PAYLOAD0;
			break;
		case STATE_I_PLEN16:
			rc = tbuf_read(ws, 2 - ws->t_off);
			if (rc < 0)
				return rc;
			if (ws->t_off < 2)
				continue;
			ws->t_off = 0;

			len = get_u16(ws->t_buf);
			if (len < 126)
				return WS_E_BAD_LEN;
			ws->i_len = len;
			ws->i_state = ws->srv ? STATE_I_MASK : STATE_I_PAYLOAD0;
			break;
		case STATE_I_PLEN64:
			rc = tbuf_read(ws, 8 - ws->t_off);
			if (rc < 0)
				return rc;
			if (ws->t_off < 8)
				continue;
			ws->t_off = 0;

			m = get_u64(ws->t_buf);
			if (m < 0x10000)
				return WS_E_BAD_LEN;
			if (m > 0x7FFFFFFFFFFFFFFF || m > SIZE_MAX)
				return WS_E_BAD_LEN;

			len = (size_t)m;
			ws->i_len = len;
			ws->i_state = ws->srv ? STATE_I_MASK : STATE_I_PAYLOAD0;
			break;
		case STATE_I_PAYLOAD0:
			assert(ws->i_len > 0);
			if (ws->limit && ws->i_len > ws->limit)
				return WS_E_TOO_LONG;
			ws->i_state = STATE_I_PAYLOAD;
			/* THROUGH */
		case STATE_I_PAYLOAD:
			assert(ws->i_len > 0);
			len = ws->i_len > WS_I_BUF_LEN(ws) ?
					WS_I_BUF_LEN(ws) : ws->i_len;
			rc = read_n(ws, WS_I_BUF(ws), len);
			if (rc < 0)
				return rc;

			if (ws->srv) {
				p = WS_I_BUF(ws);
				for (i = 0; i < (size_t)rc; i++)
					p[i] ^= ws->i_mskbuf[ws->i_imsk++ % 4];
			}

			ws->i_off += rc;
			ws->i_len -= rc;

			assert(WS_IO_BUF_SIZE - ws->i_uoff >= 125);
			/* Read a whole control frame. */
			if (CTRL(ws->op) && ws->i_len > 0)
				continue;

			ws->i_data = ws->i_buf;
			ws->i_left = ws->i_off;
			if (CTRL(ws->op)) {
				/* uoff is related to prev CONT text frame. */
				ws->i_data += ws->i_uoff;
				ws->i_left -= ws->i_uoff;
			}

			if (ws->op == OP_CLOSE) {
				ws->ecode = get_u16(ws->i_data);
				if (!(ws->ecode >= 1000 && ws->ecode <= 4999))
					return WS_E_BAD_ECODE;
				ws->i_data += 2;
				ws->i_left -= 2;
			}

			if (ws->utf8_on &&
			    ((ws->op == OP_CLOSE && ws->i_left > 0) ||
			      ws->op == OP_TEXT)) {
				size_t u;
				rc = utf8len(ws->i_data, ws->i_left);
				if (rc < 0)
					return WS_E_NON_UTF8;
				u = ws->i_left - rc;
				/* i_left may be truncated because of
				 * the last partial UTF8 character. */
				if (ws->op == OP_CLOSE && u > 0)
					return WS_E_NON_UTF8;
				/* We have a single partial UTF8 character. */
				if (ws->op == OP_TEXT && u == ws->i_left) {
					/* The whole frame is read. */
					if (ws->i_len == 0) {
						if (!ws->cont)
							return WS_E_NON_UTF8;
						/* CONT may be incompleted. */
						ws->i_uoff = ws->i_off = u;
						ws->i_state = STATE_I_HDR;
						/* Read next frame, preserve
						 * incompleted UTF8 character. */
						continue;
					}
					/* Can't provide a user even with a
					 * single UTF8 character, read more. */
					continue;
				}
				/* i_left is a valid UTF-8 sequence. */
				ws->i_left = rc;
				assert(ws->i_left > 0);
			}

			ws->i_state = CTRL(ws->op) ?
					STATE_I_CTRL : STATE_I_DRAIN;
			break;
		case STATE_I_CTRL:
			assert(CTRL(ws->op));
			ws->ctrlsz = ws->i_left;
			ws->ctrl = ws->i_left > 0 ? ws->i_data : NULL;
			ws->i_left = 0;
			ws->i_off = ws->i_uoff;
			ws->i_state = STATE_I_HDR;
			return ws->op == OP_CLOSE ? WS_E_OP_CLOSE :
			       ws->op == OP_PING  ? WS_E_OP_PING :
						    WS_E_OP_PONG;
		case STATE_I_DRAIN:
			if (hnd) {
				n = 0;
				arg->h.hnd(arg->h.opaque, ws->i_data,
						ws->i_left, ws->op == OP_TEXT);
				ws->i_data += ws->i_left;
				ws->i_left = 0;
			} else {
				n = ws->i_left > arg->r.n ? arg->r.n : ws->i_left;
				memcpy(arg->r.buf, ws->i_data, n);
				*arg->r.txt = ws->op == OP_TEXT;
				ws->i_data += n;
				ws->i_left -= n;
			}

			if (ws->i_left == 0) {
				/* Partial UTF-8 sequence. */
				size_t u = WS_I_BUF(ws) - ws->i_data;
				if (u > 0)
					memmove(ws->i_buf, ws->i_data, u);
				ws->i_uoff = ws->i_off = u;
				ws->i_state = ws->i_len > 0 ?
					STATE_I_PAYLOAD : STATE_I_HDR;
			}

			if (hnd)
				break;
			return (ssize_t)n;
		default:
			abort();
		}
	}

	return -1;
}

ssize_t ws_read(WebSocket *ws, void *buf, size_t n, int *txt)
{
	union ws_arg arg;
	arg.r.buf = buf;
	arg.r.n   = n;
	arg.r.txt = txt;
	return ws_handler(ws, &arg, 0);
}

int ws_parse(WebSocket *ws, void *opaque,
	     void (*hnd)(void *opaque, const void *buf, size_t n, int txt))
{
	union ws_arg arg;
	arg.h.hnd    = hnd;
	arg.h.opaque = opaque;
	return ws_handler(ws, &arg, 1);
}

void ws_set_data_limit(WebSocket *ws, size_t limit)
{
	ws->limit = limit;
}

void ws_set_check_utf8(WebSocket *ws, int v)
{
	ws->utf8_on = v ? 1 : 0;
}

