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

struct crc16_context {
    struct csum_context csum;
    char result[32];
    uint16_t crc;
};

#define csum_to_crc16(ptr) \
    container_of(ptr, struct crc16_context, csum)

static const char *
crc16_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct crc16_context *crc16 = csum_to_crc16(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        crc16->crc = bfdev_crc16(buff, length, crc16->crc);
        consumed += length;
    }

    sprintf(crc16->result, "%#06x", crc16->crc);
    return crc16->result;
}

static struct csum_context *
crc16_prepare(const char *args, unsigned long flags)
{
    struct crc16_context *crc16;

    crc16 = bfdev_zalloc(NULL, sizeof(*crc16));
    if (unlikely(!crc16))
        return NULL;

    if (args)
        crc16->crc = (uint16_t)strtoul(args, NULL, 0);
    
    return &crc16->csum;
}

static void
crc16_destroy(struct csum_context *ctx)
{
    struct crc16_context *crc16 = csum_to_crc16(ctx);
    bfdev_free(NULL, crc16);
}

static struct csum_algo crc16 = {
    .name = "crc16",
    .prepare = crc16_prepare,
    .destroy = crc16_destroy,
    .compute = crc16_compute,
};

static int __ctor crc16_init(void)
{
    return csum_register(&crc16);
}

static void __dtor crc16_exit(void)
{
    csum_unregister(&crc16);
}
