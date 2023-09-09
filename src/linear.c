/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <csum.h>

static size_t
linear_next(struct csum_context *ctx, struct csum_state *sta,
            uintptr_t consumed, const void **dest)
{
    struct csum_linear *linear = sta->pdata;

	if (bfdev_likely(consumed < linear->length)) {
		*dest = linear->data + consumed;
		return linear->length - consumed;
	}

    return 0;
}

const char *
csum_linear_compute(struct csum_context *ctx, struct csum_linear *linear,
                   const void *data, size_t length)
{
    struct csum_algo *algo = ctx->algo;

    linear->data = data;
    linear->length = length;
    linear->sta.offset = 0;
    linear->sta.pdata = linear;
    ctx->next_block = linear_next;

    return algo->compute(ctx, &linear->sta);
}

const char *
csum_linear_next(struct csum_context *ctx, struct csum_linear *linear)
{
    struct csum_algo *algo = ctx->algo;
    return algo->compute(ctx, &linear->sta);
}
