/*
 * Copyright (c) 1995-2001 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef TEST
#include <stdio.h>
#include <getarg.h>
#include <err.h>
#endif
#include "base64.h"
#include "roken.h"

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
pos(char c)
{
    switch (c) {
	case 'A': return 0;
	case 'B': return 1;
	case 'C': return 2;
	case 'D': return 3;
	case 'E': return 4;
	case 'F': return 5;
	case 'G': return 6;
	case 'H': return 7;
	case 'I': return 8;
	case 'J': return 9;
	case 'K': return 10;
	case 'L': return 11;
	case 'M': return 12;
	case 'N': return 13;
	case 'O': return 14;
	case 'P': return 15;
	case 'Q': return 16;
	case 'R': return 17;
	case 'S': return 18;
	case 'T': return 19;
	case 'U': return 20;
	case 'V': return 21;
	case 'W': return 22;
	case 'X': return 23;
	case 'Y': return 24;
	case 'Z': return 25;
	case 'a': return 26;
	case 'b': return 27;
	case 'c': return 28;
	case 'd': return 29;
	case 'e': return 30;
	case 'f': return 31;
	case 'g': return 32;
	case 'h': return 33;
	case 'i': return 34;
	case 'j': return 35;
	case 'k': return 36;
	case 'l': return 37;
	case 'm': return 38;
	case 'n': return 39;
	case 'o': return 40;
	case 'p': return 41;
	case 'q': return 42;
	case 'r': return 43;
	case 's': return 44;
	case 't': return 45;
	case 'u': return 46;
	case 'v': return 47;
	case 'w': return 48;
	case 'x': return 49;
	case 'y': return 50;
	case 'z': return 51;
	case '0': return 52;
	case '1': return 53;
	case '2': return 54;
	case '3': return 55;
	case '4': return 56;
	case '5': return 57;
	case '6': return 58;
	case '7': return 59;
	case '8': return 60;
	case '9': return 61;
	case '+': return 62;
	case '/': return 63;
	default: return -1;
    }
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_base64_encode(const void *data, int size, char **str)
{
    char *s, *p;
    int i;
    uint32_t c;
    const unsigned char *q;

    if (size > INT_MAX/4 || size < 0) {
	*str = NULL;
        errno = ERANGE;
	return -1;
    }

    p = s = (char *) malloc(size * 4 / 3 + 4);
    if (p == NULL) {
        *str = NULL;
	return -1;
    }
    q = (const unsigned char *) data;

    for (i = 0; i < size;) {
	c = q[i++];
	c *= 256;
	if (i < size)
	    c += q[i];
	i++;
	c *= 256;
	if (i < size)
	    c += q[i];
	i++;
	p[0] = base64_chars[(c & 0x00fc0000) >> 18];
	p[1] = base64_chars[(c & 0x0003f000) >> 12];
	p[2] = base64_chars[(c & 0x00000fc0) >> 6];
	p[3] = base64_chars[(c & 0x0000003f) >> 0];
	if (i > size)
	    p[3] = '=';
	if (i > size + 1)
	    p[2] = '=';
	p += 4;
    }
    *p = 0;
    *str = s;
    return (int) (p - s);
}

#define DECODE_ERROR 0xffffffff
#define DECODE_DONE 0xfffffffe

static uint32_t
token_decode(const char *token)
{
    int i;
    uint32_t val = 0;
    unsigned marker = 0;
    for (i = 0; i < 4; i++) {
	if (!token[i]) {
	    return (i == 0) ? DECODE_DONE : DECODE_ERROR;
	}
	val *= 64;
	if (token[i] == '=')
	    marker++;
	else if (marker > 0)
	    return DECODE_ERROR;
	else {
	    int tmp = pos(token[i]);
	    if (tmp == -1) {
		return (i == 0) ? DECODE_DONE : DECODE_ERROR;
	    }
	    val += tmp;
	}
    }
    if (marker > 2)
	return DECODE_ERROR;
    return (marker << 24) | val;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_base64_decode(const char *str, void *data)
{
    const char *p;
    unsigned char *q;

    q = data;
    for (p = str; ; p += 4) {
	uint32_t val = token_decode(p);
	unsigned int marker = (val >> 24) & 0xff;
	if (val == DECODE_ERROR) {
            errno = EINVAL;
	    return -1;
        } else if (val == DECODE_DONE) {
	    break;
        }
	*q++ = (val >> 16) & 0xff;
	if (marker < 2)
	    *q++ = (val >> 8) & 0xff;
	if (marker < 1)
	    *q++ = val & 0xff;
    }
    if (q - (unsigned char *) data > INT_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    return q - (unsigned char *) data;
}

#ifdef TEST
static int decode_flag;
static int help_flag;

/*
 * The short options are compatible with a subset of the FreeBSD contrib
 * vis(1).  Heimdal additions have long option names only.
 */
static struct getargs args[] = {
    { "decode", 'd', arg_flag, &decode_flag, "Decode", NULL },
    { "help", 'h', arg_flag, &help_flag, "Print help message", NULL },
};
static size_t num_args = sizeof(args)/sizeof(args[0]);

int
main(int argc, char **argv)
{
    unsigned char *buf = NULL;
    size_t buflen = 0;
    size_t bufsz = 0;
    int goptind = 0;
    int ret;

    setprogname("rkbase64");
    if (getarg(args, num_args, argc, argv, &goptind) || help_flag) {
        arg_printusage(args, num_args, NULL, "FILE | -");
        return help_flag ? 0 : 1;
    }

    argc -= goptind;
    argv += goptind;

    if (help_flag)
        return arg_printusage(args, num_args, NULL, "FILE | -- -"), 0;
    if (argc != 1)
        return arg_printusage(args, num_args, NULL, "FILE | -- -"), 1;

    if (strcmp(argv[0], "-") == 0) {
        unsigned char *tmp;
        unsigned char d[4096];
        size_t bytes;

        while (!feof(stdin) && !ferror(stdin)) {
            bytes = fread(d, 1, sizeof(d), stdin);
            if (bytes == 0)
                continue;
            if (buflen + bytes > bufsz) {
                if ((tmp = realloc(buf, bufsz + (bufsz >> 2) + sizeof(d))) == NULL)
                    err(1, "Could not read stdin");
                buf = tmp;
                bufsz = bufsz + (bufsz >> 2) + sizeof(d);
            }
            memcpy(buf + buflen, d, bytes);
            buflen += bytes;
        }
        if (ferror(stdin))
            err(1, "Could not read stdin");
    } else {
        void *d;
        if ((errno = rk_undumpdata(argv[0], &d, &bufsz)))
            err(1, "Could not read %s", argv[0]);
        buflen = bufsz;
        buf = d;
    }

    if (decode_flag) {
        unsigned char *d;

        if (buflen == bufsz) {
            unsigned char *tmp;

            if ((tmp = realloc(buf, bufsz + 1)) == NULL)
                err(1, "Could not decode data");
            buf = tmp;
            bufsz++;
        }
        buf[buflen] = '\0';

        if ((d = malloc(buflen * 3 / 4 + 4)) == NULL)
            err(1, "Could not decode data");

        if ((ret = rk_base64_decode((const char *)buf, d)) < 0)
            err(1, "Could not decode data");
        if (fwrite(d, ret, 1, stdout) != 1)
            err(1, "Could not write decoded data");
        free(d);
    } else if (buf) { /* buf can be NULL if we read from an empty file */
        char *e;

        if ((ret = rk_base64_encode(buf, buflen, &e)) < 0)
            err(1, "Could not encode data");
        if (fwrite(e, ret, 1, stdout) != 1)
            err(1, "Could not write decoded data");
        free(e);
        if (fwrite("\n", 1, 1, stdout) != 1)
            err(1, "Could not write decoded data");
    }
    free(buf);
    return 0;
}
#endif
