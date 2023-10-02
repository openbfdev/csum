/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <csum.h>
#include <stdio.h>
#include <stdlib.h>
#include <bfdev/allocator.h>
#include <bfdev/crc.h>

struct crc8_context {
    struct csum_context csum;
    char result[32];
    uint8_t crc;
};

#define csum_to_crc8(ptr) \
    bfdev_container_of(ptr, struct crc8_context, csum)

static const char *
crc8_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct crc8_context *crc8 = csum_to_crc8(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        crc8->crc = bfdev_crc8(buff, length, crc8->crc);
        consumed += length;
    }

    sprintf(crc8->result, "%#04x", crc8->crc);
    sta->offset = consumed;

    return crc8->result;
}

static struct csum_context *
crc8_prepare(const char *args, unsigned long flags)
{
    struct crc8_context *crc8;

    crc8 = bfdev_zalloc(NULL, sizeof(*crc8));
    if (bfdev_unlikely(!crc8))
        return NULL;

    if (args)
        crc8->crc = (uint8_t)strtoul(args, NULL, 0);

    return &crc8->csum;
}

static void
crc8_destroy(struct csum_context *ctx)
{
    struct crc8_context *crc8 = csum_to_crc8(ctx);
    bfdev_free(NULL, crc8);
}

static struct csum_algo crc8 = {
    .name = "crc8",
    .prepare = crc8_prepare,
    .destroy = crc8_destroy,
    .compute = crc8_compute,
};

static int __bfdev_ctor
crc8_init(void)
{
    return csum_register(&crc8);
}

static void __bfdev_dtor
crc8_exit(void)
{
    csum_unregister(&crc8);
}
