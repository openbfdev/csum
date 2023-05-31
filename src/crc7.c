/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <csum.h>
#include <stdio.h>
#include <stdlib.h>
#include <bfdev/allocator.h>
#include <bfdev/attributes.h>
#include <bfdev/crc.h>

struct ccitt_context {
    struct csum_context csum;
    char result[32];
    uint8_t crc;
};

#define csum_to_ccitt(ptr) \
    container_of(ptr, struct ccitt_context, csum)

static const char *
ccitt_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct ccitt_context *ccitt = csum_to_ccitt(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        ccitt->crc = bfdev_crc7(buff, length, ccitt->crc);
        consumed += length;
    }

    sprintf(ccitt->result, "%#02x", ccitt->crc);
    return ccitt->result;
}

static struct csum_context *
ccitt_prepare(const char *args, unsigned long flags)
{
    struct ccitt_context *ccitt;

    ccitt = bfdev_zalloc(NULL, sizeof(*ccitt));
    if (unlikely(!ccitt))
        return NULL;

    if (args)
        ccitt->crc = (uint8_t)strtoul(args, NULL, 0);

    return &ccitt->csum;
}

static void
ccitt_destroy(struct csum_context *ctx)
{
    struct ccitt_context *ccitt = csum_to_ccitt(ctx);
    bfdev_free(NULL, ccitt);
}

static struct csum_algo ccitt = {
    .name = "crc7",
    .prepare = ccitt_prepare,
    .destroy = ccitt_destroy,
    .compute = ccitt_compute,
};

static int __ctor ccitt_init(void)
{
    return csum_register(&ccitt);
}

static void __dtor ccitt_exit(void)
{
    csum_unregister(&ccitt);
}
