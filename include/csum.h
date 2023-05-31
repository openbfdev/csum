/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#ifndef _CSUM_H_
#define _CSUM_H_

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <bfdev/list.h>

struct csum_state {
    uintptr_t offset;
    void *pdata;
};

struct csum_linear {
    struct csum_state sta;
    const void *data;
    size_t length;
};

struct csum_context {
    struct csum_algo *algo;
    unsigned long flags;
    size_t (*next_block)(struct csum_context *tsc, struct csum_state *sta,
                         uintptr_t consumed, const void **dest);
};

struct csum_algo {
    struct bfdev_list_head list;
    struct algorithm_ops *ops;

    const char *name;
    const char *desc;

    struct csum_context *(*prepare)(const char *args, unsigned long flags);
    void (*destroy)(struct csum_context *ctx);
    const char *(*compute)(struct csum_context *ctx, struct csum_state *sta);
};

static inline const char *
csum_compute(struct csum_context *ctx, struct csum_state *sta)
{
    struct csum_algo *algo = ctx->algo;
    sta->offset = 0;
    return algo->compute(ctx, sta);
}

static inline const char *
csum_next(struct csum_context *ctx, struct csum_state *sta)
{
    struct csum_algo *algo = ctx->algo;
    return algo->compute(ctx, sta);
}

static inline void
csum_destroy(struct csum_context *ctx)
{
    struct csum_algo *algo = ctx->algo;
    algo->destroy(ctx);
}

extern struct bfdev_list_head csum_algos;

extern const char *
csum_linear_compute(struct csum_context *ctx, struct csum_linear *linear, const void *data, size_t length);
extern const char *
csum_linear_next(struct csum_context *ctx, struct csum_linear *linear);

extern struct csum_context *csum_prepare(const char *name, const char *args, unsigned long flags);
extern int csum_register(struct csum_algo *algo);
extern int csum_unregister(struct csum_algo *algo);

#endif /* _CSUM_H_ */
