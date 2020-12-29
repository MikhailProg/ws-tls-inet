#ifndef WS_H
#define WS_H

#ifndef WS_IO_BUF_SIZE
//#  define WS_IO_BUF_SIZE	8192
#  define WS_IO_BUF_SIZE	16384
#endif

#include <stdint.h>

typedef struct WebSocket WebSocket;

struct WebSocket {
	void		*ctx;
	ssize_t		(*recv)(void *ctx, void *buf, size_t n);
	ssize_t		(*send)(void *ctx, const void *buf, size_t n);
	unsigned char	srv;
	unsigned char	op;
	unsigned char	cont;
	unsigned char	utf8_on;
	int		err;
	unsigned char	*ctrl;
	unsigned char	ctrlsz;
	uint16_t	ecode;
	char		*sec;
	size_t		limit;

	int		h_state;
	size_t		h_off;
	size_t		h_left;
	unsigned char	*h_buf;
	unsigned char	*h_data;

	int		i_state;
	size_t		i_imsk;
	unsigned char	i_mskbuf[4];
	size_t		i_len;
	unsigned char	*i_buf;
	size_t		i_off;
	unsigned char	*i_data;
	size_t		i_left;
	size_t		i_uoff;
	unsigned char	t_buf[8];
	unsigned char	t_off;

	int		o_state;
	size_t		o_imsk;
	unsigned char	o_mskbuf[4];
	size_t		o_len;
	unsigned char	*o_buf;
	size_t		o_off;
	unsigned char	*o_data;
	size_t		o_left;
	size_t		o_offall;
	size_t		o_lenall;
};

/* 0 in case of success and -1 in case of failure. */
int ws_init(WebSocket *ws, int srv);
void ws_deinit(WebSocket *ws);

/* handshake is a bit naive, a user can use its own handshake and than
 * starts using framing functions ws_*_write(), ws_read(), ws_parse(). */

/* 0 in case of success or < 0 in case of failure (see err code below). */
int ws_handshake(WebSocket *ws, const char *host,
				const char *uri, const char *uhdrs);

/* ws_txt_write() may send less than n if the buf contains an incomplete
 * UTF-8 character at the buf's end. */
ssize_t ws_txt_write(WebSocket *ws, const void *buf, size_t n);

ssize_t ws_bin_write(WebSocket *ws, const void *buf, size_t n);

/* ws_read and ws_parse garantie to return utf8 complete
 * data for TEXT frame. */
ssize_t ws_read(WebSocket *ws, void *buf, size_t n, int *txt);

int ws_parse(WebSocket *ws, void *opaque,
	     void (*hnd)(void *opaque, const void *buf, size_t n, int txt));

/* For ping, pong, close 0 in case of success or < 0 in case of
 * failure (see err code below). */
int ws_ping(WebSocket *ws, const void *buf, size_t n);
int ws_pong(WebSocket *ws, const void *buf, size_t n);
int ws_close(WebSocket *ws, uint16_t ecode, const void *msg, size_t n);

void ws_set_bio(WebSocket *ws, void *ctx,
		 ssize_t (*send)(void *ctx, const void *buf, size_t n),
		 ssize_t (*recv)(void *ctx, void *buf, size_t n));

void ws_set_data_limit(WebSocket *ws, size_t limit);

/* UTF-8 check is enabled by default. */
void ws_set_check_utf8(WebSocket *ws, int v);

int ws_check_pending(const WebSocket *ws);

#define WS_E_FAULT_FRAME	-0x1000
#define WS_E_BAD_LEN		-0x1001
#define WS_E_NON_UTF8		-0x1002
#define WS_E_BAD_ECODE		-0x1003
#define WS_E_WANT_READ		-0x1004
#define WS_E_WANT_WRITE		-0x1005
#define WS_E_BAD_OPCODE		-0x1006
#define WS_E_IO			-0x1007
#define WS_E_EOF		-0x1008
#define WS_E_HANDSHAKE		-0x1009
#define WS_E_HTTP_REQ_LINE	-0x100A
#define WS_E_HTTP_HDR		-0x100B
#define WS_E_OP_CLOSE		-0x100C
#define WS_E_OP_PING		-0x100D
#define WS_E_OP_PONG		-0x100E
#define WS_E_HTTP_RES_LINE	-0x100F
#define WS_E_EXPECT_MASK	-0x1010
#define WS_E_UNEXPECTED_MASK	-0x1011
#define WS_E_TOO_LONG		-0x1012
#define WS_E_UTF8_INCOPMLETE	-0x1013
#define WS_E_HTTP_REQ_URI	-0x1014
#define WS_E_HTTP_EXTRA_DATA	-0x1015

#endif /* WS_H */
