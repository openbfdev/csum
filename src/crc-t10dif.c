/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <csum.h>
#include <stdio.h>
#include <stdlib.h>
#include <bfdev/allocator.h>
#include <bfdev/crc.h>

struct t10dif_context {
    struct csum_context csum;
    char result[32];
    uint16_t crc;
};

#define csum_to_t10dif(ptr) \
    bfdev_container_of(ptr, struct t10dif_context, csum)

static const char *
t10dif_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct t10dif_context *t10dif = csum_to_t10dif(ctx);
    uintptr_t consumed = sta->offset;
    size_t length;
    const void *buff;

    for (;;) {
        length = ctx->next_block(ctx, sta, consumed, &buff);
        if (!length)
            break;

        t10dif->crc = bfdev_crc_t10dif(buff, length, t10dif->crc);
        consumed += length;
    }

    sprintf(t10dif->result, "%#06x", t10dif->crc);
    sta->offset = consumed;

    return t10dif->result;
}

static struct csum_context *
t10dif_prepare(const char *args, unsigned long flags)
{
    struct t10dif_context *t10dif;

    t10dif = bfdev_zalloc(NULL, sizeof(*t10dif));
    if (bfdev_unlikely(!t10dif))
        return NULL;

    if (args)
        t10dif->crc = (uint16_t)strtoul(args, NULL, 0);

    return &t10dif->csum;
}

static void
t10dif_destroy(struct csum_context *ctx)
{
    struct t10dif_context *t10dif = csum_to_t10dif(ctx);
    bfdev_free(NULL, t10dif);
}

static struct csum_algo t10dif = {
    .name = "crc-t10dif",
    .prepare = t10dif_prepare,
    .destroy = t10dif_destroy,
    .compute = t10dif_compute,
};

static int __bfdev_ctor
t10dif_init(void)
{
    return csum_register(&t10dif);
}

static void __bfdev_dtor
t10dif_exit(void)
{
    csum_unregister(&t10dif);
}
