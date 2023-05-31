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

struct crc4_context {
    struct csum_context csum;
    char result[32];
    uint8_t crc;
};

#define crc4(ptr) \
    container_of(ptr, struct crc4_context, csum)

static const char *
crc4_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct crc4_context *crc4 = crc4(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        crc4->crc = bfdev_crc4(buff, length, crc4->crc);
        consumed += length;
    }

    sprintf(crc4->result, "%#02x", crc4->crc);
    return crc4->result;
}

static struct csum_context *
crc4_prepare(const char *args, unsigned long flags)
{
    struct crc4_context *crc4;

    crc4 = bfdev_zalloc(NULL, sizeof(*crc4));
    if (unlikely(!crc4))
        return NULL;

    if (args)
        crc4->crc = (uint8_t)strtoul(args, NULL, 0);

    return &crc4->csum;
}

static void
crc4_destroy(struct csum_context *ctx)
{
    struct crc4_context *crc4 = crc4(ctx);
    bfdev_free(NULL, crc4);
}

static struct csum_algo crc4 = {
    .name = "crc4",
    .prepare = crc4_prepare,
    .destroy = crc4_destroy,
    .compute = crc4_compute,
};

static int __ctor crc4_init(void)
{
    return csum_register(&crc4);
}

static void __dtor crc4_exit(void)
{
    csum_unregister(&crc4);
}
