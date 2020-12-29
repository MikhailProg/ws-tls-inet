/*
 *  RFC 1521 base64 encoding/decoding
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <stdint.h>
#include <stdio.h>

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL	-0x002A
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER	-0x002C

static const unsigned char base64_enc_map[64] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', '+', '/'
};

#define BASE64_SIZE_T_MAX  ((size_t) -1)/* SIZE_T_MAX is not standard */

/*
 * Encode a buffer into base64 format
 */
int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
				const unsigned char *src, size_t slen)
{
	size_t i, n;
	int C1, C2, C3;
	unsigned char *p;

	if (slen == 0) {
		*olen = 0;
		return (0);
	}

	n = slen / 3 + (slen % 3 != 0);

	if (n > (BASE64_SIZE_T_MAX - 1) / 4) {
		*olen = BASE64_SIZE_T_MAX;
		return (MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
	}

	n *= 4;

	if ((dlen < n + 1) || (NULL == dst)) {
		*olen = n + 1;
		return (MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
	}

	n = (slen / 3) * 3;

	for (i = 0, p = dst; i < n; i += 3) {
		C1 = *src++;
		C2 = *src++;
		C3 = *src++;

		*p++ = base64_enc_map[(C1 >> 2) & 0x3F];
		*p++ = base64_enc_map[(((C1 &  3) << 4) + (C2 >> 4)) & 0x3F];
		*p++ = base64_enc_map[(((C2 & 15) << 2) + (C3 >> 6)) & 0x3F];
		*p++ = base64_enc_map[C3 & 0x3F];
	}

	if (i < slen) {
		C1 = *src++;
		C2 = ((i + 1) < slen) ? *src++ : 0;

		*p++ = base64_enc_map[(C1 >> 2) & 0x3F];
		*p++ = base64_enc_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];

		if ((i + 1) < slen)
			*p++ = base64_enc_map[((C2 & 15) << 2) & 0x3F];
		else *p++ = '=';

		*p++ = '=';
	}

	*olen = p - dst;
	*p = 0;

	return (0);
}

int base64encode(unsigned char *dst, size_t dlen, size_t *olen,
		 const unsigned char *src, size_t slen)
{
	return mbedtls_base64_encode(dst, dlen, olen, src, slen);
}

