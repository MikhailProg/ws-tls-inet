#ifndef BASE64_H
#define BASE64_H

int base64encode(unsigned char *dst, size_t dlen, size_t *olen,
			const unsigned char *src, size_t slen);
#endif /* BASE64_H */
