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

struct crc64_context {
    struct csum_context csum;
    char result[32];
    uint64_t crc;
};

#define csum_to_crc64(ptr) \
    container_of(ptr, struct crc64_context, csum)

static const char *
crc64_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct crc64_context *crc64 = csum_to_crc64(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        crc64->crc = bfdev_crc64(buff, length, crc64->crc);
        consumed += length;
    }

    sprintf(crc64->result, "%#018llx", (unsigned long long)crc64->crc);
    sta->offset = consumed;

    return crc64->result;
}

static struct csum_context *
crc64_prepare(const char *args, unsigned long flags)
{
    struct crc64_context *crc64;

    crc64 = bfdev_zalloc(NULL, sizeof(*crc64));
    if (unlikely(!crc64))
        return NULL;

    if (args)
        crc64->crc = (uint64_t)strtoul(args, NULL, 0);

    return &crc64->csum;
}

static void
crc64_destroy(struct csum_context *ctx)
{
    struct crc64_context *crc64 = csum_to_crc64(ctx);
    bfdev_free(NULL, crc64);
}

static struct csum_algo crc64 = {
    .name = "crc64",
    .prepare = crc64_prepare,
    .destroy = crc64_destroy,
    .compute = crc64_compute,
};

static int __ctor crc64_init(void)
{
    return csum_register(&crc64);
}

static void __dtor crc64_exit(void)
{
    csum_unregister(&crc64);
}
