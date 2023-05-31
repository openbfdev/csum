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

struct rocksoft_context {
    struct csum_context csum;
    char result[32];
    uint64_t crc;
};

#define csum_to_rocksoft(ptr) \
    container_of(ptr, struct rocksoft_context, csum)

static const char *
rocksoft_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct rocksoft_context *rocksoft = csum_to_rocksoft(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        rocksoft->crc = bfdev_crc_rocksoft(buff, length, rocksoft->crc);
        consumed += length;
    }

    sprintf(rocksoft->result, "%#018llx", (unsigned long long)rocksoft->crc);
    return rocksoft->result;
}

static struct csum_context *
rocksoft_prepare(const char *args, unsigned long flags)
{
    struct rocksoft_context *rocksoft;

    rocksoft = bfdev_zalloc(NULL, sizeof(*rocksoft));
    if (unlikely(!rocksoft))
        return NULL;

    rocksoft->crc = (uint64_t)strtoul(args, NULL, 0);
    return &rocksoft->csum;
}

static void
rocksoft_destroy(struct csum_context *ctx)
{
    struct rocksoft_context *rocksoft = csum_to_rocksoft(ctx);
    bfdev_free(NULL, rocksoft);
}

static struct csum_algo rocksoft = {
    .name = "crc-rocksoft",
    .prepare = rocksoft_prepare,
    .destroy = rocksoft_destroy,
    .compute = rocksoft_compute,
};

static int __ctor rocksoft_init(void)
{
    return csum_register(&rocksoft);
}

static void __dtor rocksoft_exit(void)
{
    csum_unregister(&rocksoft);
}
