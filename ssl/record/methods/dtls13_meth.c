/*
 * Copyright 2018-2023 The OpenSSL Project Authors. All Rights Reserved.
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

int dtls13_prepare_unified_header(OSSL_RECORD_LAYER *rl,
                               WPACKET *thispkt,
                               TLS_RL_RECORD *thiswr,
                               OSSL_RECORD_TEMPLATE *templ,
                               unsigned int rectype,
                               unsigned char **recdata)
{
    size_t maxcomplen;

    *recdata = NULL;

    maxcomplen = templ->buflen;
    if (rl->compctx != NULL)
        maxcomplen += SSL3_RT_MAX_COMPRESSED_OVERHEAD;

    /* DTLSCiphertext. TODO (DTLSv1.3): Ensure that we always use SSL3_RT_APPLICATION_DATA when encrypting in DTLS 1.3
    (as in TLS 1.3, see tls13_get_record_type()) or alternatively add required conditionals for capturing all 
    DTLSCiphertext messages before entering this function */
    thiswr->unified_hdr.cbit_is_set = 0;
    /*TODO (DTLSv1.3): statically forced to use 16-bit sequence id right now, implement optional Sequence Number field*/
    thiswr->unified_hdr.sbit_is_set = 1;
    /*TODO (DTLSv1.3): statically forced to use 16-bit length field right now, implement optional Length field*/
    thiswr->unified_hdr.lbit_is_set = 1;

    /*First byte*/
    thiswr->unified_hdr.first_byte = DTLS13_FIXED_BITS;

    if (thiswr->unified_hdr.cbit_is_set) {
        thiswr->unified_hdr.first_byte |= DTLS13_CBIT;
    }
    if (thiswr->unified_hdr.sbit_is_set) {
        thiswr->unified_hdr.first_byte |= DTLS13_SBIT;
    }
    if (thiswr->unified_hdr.lbit_is_set) {
        thiswr->unified_hdr.first_byte |= DTLS13_LBIT;
    }

    /* Extracting low-order bytes (big-endian)*/
    if (thiswr->unified_hdr.sbit_is_set) {
        if (SEQ_NUM_SIZE < 2) {
            goto err;
        }
        /* Low-order 2 bytes*/
        memcpy(thiswr->unified_hdr.seq, rl->sequence + (SEQ_NUM_SIZE - 2), 2);
    } else {
        if (SEQ_NUM_SIZE < 1) {
            goto err;
        }
        /* Low-order 8 byte*/
        thiswr->unified_hdr.seq[0] = rl->sequence[SEQ_NUM_SIZE - 1];
    }

    /* The two low bits (0x03) include the low-order two bits of the epoch.*/
    thiswr->unified_hdr.first_byte |= (rl->epoch & DTLS13_EPOCH_MASK);

    if (!WPACKET_put_bytes_u8(thispkt, thiswr->unified_hdr.first_byte)
        /* TODO (DTLSv1.3): add support for Connection ID (CID), length as negotiated*/
        || !WPACKET_put_bytes_u8(thispkt, thiswr->unified_hdr.seq[0])
        || !(thiswr->unified_hdr.sbit_is_set
            ? WPACKET_put_bytes_u8(thispkt, thiswr->unified_hdr.seq[1]) : 1)
        || !(thiswr->unified_hdr.lbit_is_set
            ? WPACKET_put_bytes_u16(thispkt, templ->buflen) : 1)
        || (rl->eivlen > 0
            && !WPACKET_allocate_bytes(thispkt, rl->eivlen, NULL))
        || (maxcomplen > 0
            && !WPACKET_reserve_bytes(thispkt, maxcomplen,
                                    recdata))) {
        goto err;
    }

    thiswr->unified_hdr.valid = 1;

    return 1;

err:
    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
    return 0;
}