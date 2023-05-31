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

struct itut_context {
    struct csum_context csum;
    char result[32];
    uint16_t crc;
};

#define csum_to_itut(ptr) \
    container_of(ptr, struct itut_context, csum)

static const char *
itut_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct itut_context *itut = csum_to_itut(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        itut->crc = bfdev_crc_itut(buff, length, itut->crc);
        consumed += length;
    }

    sprintf(itut->result, "%#06x", itut->crc);
    return itut->result;
}

static struct csum_context *
itut_prepare(const char *args, unsigned long flags)
{
    struct itut_context *itut;

    itut = bfdev_zalloc(NULL, sizeof(*itut));
    if (unlikely(!itut))
        return NULL;

    itut->crc = (uint16_t)strtoul(args, NULL, 0);
    return &itut->csum;
}

static void
itut_destroy(struct csum_context *ctx)
{
    struct itut_context *itut = csum_to_itut(ctx);
    bfdev_free(NULL, itut);
}

static struct csum_algo itut = {
    .name = "crc-itut",
    .prepare = itut_prepare,
    .destroy = itut_destroy,
    .compute = itut_compute,
};

static int __ctor itut_init(void)
{
    return csum_register(&itut);
}

static void __dtor itut_exit(void)
{
    csum_unregister(&itut);
}
