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

struct ccittf_context {
    struct csum_context csum;
    char result[32];
    uint16_t crc;
};

#define csum_to_ccittf(ptr) \
    container_of(ptr, struct ccittf_context, csum)

static const char *
ccittf_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct ccittf_context *ccittf = csum_to_ccittf(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        ccittf->crc = bfdev_crc_ccittf(buff, length, ccittf->crc);
        consumed += length;
    }

    sprintf(ccittf->result, "%#06x", ccittf->crc);
    return ccittf->result;
}

static struct csum_context *
ccittf_prepare(const char *args, unsigned long flags)
{
    struct ccittf_context *ccittf;

    ccittf = bfdev_zalloc(NULL, sizeof(*ccittf));
    if (unlikely(!ccittf))
        return NULL;

    ccittf->crc = (uint16_t)strtoul(args, NULL, 0);
    return &ccittf->csum;
}

static void
ccittf_destroy(struct csum_context *ctx)
{
    struct ccittf_context *ccittf = csum_to_ccittf(ctx);
    bfdev_free(NULL, ccittf);
}

static struct csum_algo ccittf = {
    .name = "crc-ccittf",
    .prepare = ccittf_prepare,
    .destroy = ccittf_destroy,
    .compute = ccittf_compute,
};

static int __ctor ccittf_init(void)
{
    return csum_register(&ccittf);
}

static void __dtor ccittf_exit(void)
{
    csum_unregister(&ccittf);
}
