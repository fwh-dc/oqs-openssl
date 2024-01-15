/*
 * Copyright 2018-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../../ssl_local.h"
#include "recmethod_local.h"

#define DTLS13_FIXED_BITS   0x20
#define DTLS13_CBIT         0x10
#define DTLS13_SBIT         0x08
#define DTLS13_LBIT         0x04
#define DTLS13_EPOCH_MASK   0x03


int dtls13_prepare_record_header(OSSL_RECORD_LAYER *rl,
                               WPACKET *thispkt,
                               OSSL_RECORD_TEMPLATE *templ,
                               uint8_t rectype,
                               unsigned char **recdata)
{
    size_t maxcomplen;

    *recdata = NULL;

    maxcomplen = templ->buflen;
    if (rl->compctx != NULL)
        maxcomplen += SSL3_RT_MAX_COMPRESSED_OVERHEAD;

    if (rectype == SSL3_RT_APPLICATION_DATA) {
    /* DTLSCiphertext*/
    /* TODO (DTLSv1.3): Ensure that we always use SSL3_RT_APPLICATION_DATA when encrypting in DTLS 1.3
    (as in TLS 1.3, see tls13_get_record_type()). If not, add required conditionals for capturing all
    DTLSCiphertext messages*/
    unsigned char first_byte;

    /*TODO (DTLSv1.3): Hardcoded first byte. Statically forced to use no Connection ID,
    16-bit Sequence ID and 16-bit Length field. Implement variable length fields*/
    first_byte = DTLS13_FIXED_BITS | DTLS13_SBIT | DTLS13_LBIT; // CBIT is not set
    /* The two low bits (0x03) include the low-order two bits of the epoch.*/
    first_byte |= (rl->epoch & DTLS13_EPOCH_MASK);

    if (!WPACKET_put_bytes_u8(thispkt, first_byte)
        || !WPACKET_put_bytes_u8(thispkt, rl->sequence[SEQ_NUM_SIZE - 2])
        || !WPACKET_put_bytes_u8(thispkt, rl->sequence[SEQ_NUM_SIZE - 1])
        || !WPACKET_put_bytes_u16(thispkt, templ->buflen)
        || (rl->eivlen > 0
            && !WPACKET_allocate_bytes(thispkt, rl->eivlen, NULL))
        || (maxcomplen > 0
            && !WPACKET_reserve_bytes(thispkt, maxcomplen,
                                    recdata))) {
        goto err;
    }
    } else {
        /* DTLSPlainText record */
        if (!WPACKET_put_bytes_u8(thispkt, rectype)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!WPACKET_put_bytes_u16(thispkt, templ->version)
            || !WPACKET_put_bytes_u16(thispkt, rl->epoch)
            || !WPACKET_memcpy(thispkt, &(rl->sequence[2]), 6)
            || !WPACKET_start_sub_packet_u16(thispkt)
            || (rl->eivlen > 0
                && !WPACKET_allocate_bytes(thispkt, rl->eivlen, NULL))
            || (maxcomplen > 0
                && !WPACKET_reserve_bytes(thispkt, maxcomplen, recdata))
            ) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
    }

    return 1;

err:
    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
    return 0;
}