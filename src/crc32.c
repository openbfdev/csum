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

struct crc32_context {
    struct csum_context csum;
    char result[32];
    uint32_t crc;
};

#define csum_to_crc32(ptr) \
    container_of(ptr, struct crc32_context, csum)

static const char *
crc32_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct crc32_context *crc32 = csum_to_crc32(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        crc32->crc = bfdev_crc32(buff, length, crc32->crc);
        consumed += length;
    }

    sprintf(crc32->result, "%#010x", crc32->crc);
    sta->offset = consumed;

    return crc32->result;
}

static struct csum_context *
crc32_prepare(const char *args, unsigned long flags)
{
    struct crc32_context *crc32;

    crc32 = bfdev_zalloc(NULL, sizeof(*crc32));
    if (unlikely(!crc32))
        return NULL;

    if (args)
        crc32->crc = (uint32_t)strtoul(args, NULL, 0);

    return &crc32->csum;
}

static void
crc32_destroy(struct csum_context *ctx)
{
    struct crc32_context *crc32 = csum_to_crc32(ctx);
    bfdev_free(NULL, crc32);
}

static struct csum_algo crc32 = {
    .name = "crc32",
    .prepare = crc32_prepare,
    .destroy = crc32_destroy,
    .compute = crc32_compute,
};

static int __ctor crc32_init(void)
{
    return csum_register(&crc32);
}

static void __dtor crc32_exit(void)
{
    csum_unregister(&crc32);
}
