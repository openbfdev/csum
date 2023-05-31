/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdbool.h>
#include <string.h>
#include <csum.h>

BFDEV_LIST_HEAD(csum_algos);

static struct csum_algo *
algo_find(const char *name)
{
    struct csum_algo *walk;

    bfdev_list_for_each_entry(walk, &csum_algos, list) {
        if (!strcmp(walk->name, name))
            return walk;
    }

    return NULL;
}

static bool
algo_exist(struct csum_algo *algo)
{
    struct csum_algo *walk;

    bfdev_list_for_each_entry(walk, &csum_algos, list) {
        if (walk == algo)
            return true;
    }

    return false;
}

int
csum_register(struct csum_algo *algo)
{
    if (!algo->name || !algo->compute || !algo->prepare ||
        !algo->destroy)
        return -EINVAL;

    if (algo_find(algo->name))
        return -EALREADY;

    bfdev_list_add(&csum_algos, &algo->list);
    return 0;
}

int
csum_unregister(struct csum_algo *algo)
{
    if (!algo_exist(algo))
        return -ENOENT;

    bfdev_list_del(&algo->list);
    return 0;
}

struct csum_context *
csum_prepare(const char *name, const char *args,
               unsigned long flags)
{
    struct csum_algo *algo;
    struct csum_context *tsc;

    algo = algo_find(name);
    if (!algo)
        return NULL;

    tsc = algo->prepare(args, flags);
    if (!tsc)
        return NULL;

    tsc->algo = algo;
    tsc->flags = flags;

    return tsc;
}
