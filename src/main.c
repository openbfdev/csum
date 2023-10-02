/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <csum.h>
#include <config.h>
#include <bfdev/bits.h>
#include <bfdev/minmax.h>

#define DEF_ALGO "crc32"
#define PIPE_BUFFER 0x10000

enum {
    __CSUM_ZERO = 0,
    CSUM_ZERO = BFDEV_BIT(__CSUM_ZERO),
};

struct pipe_context {
    uint8_t buffer[PIPE_BUFFER];
    int pipe;
};

static const struct option options[] = {
    {"version",     no_argument,        0,  'v'},
    {"help",        no_argument,        0,  'h'},
    {"algorithm",   required_argument,  0,  'a'},
    {"parameter",   required_argument,  0,  'p'},
    {"zero",        no_argument,        0,  'z'},
    {"seek",        required_argument,  0,  's'},
    {"len",         required_argument,  0,  'l'},
    { }, /* NULL */
};

static size_t
pipe_next_block(struct csum_context *tsc, struct csum_state *sta,
                uintptr_t consumed, const void **dest)
{
    struct pipe_context *pctx = sta->pdata;
    ssize_t retval;

    retval = read(pctx->pipe, pctx->buffer, PIPE_BUFFER);
    if (retval < 0) {
        errno = retval;
        return 0;
    }
    *dest = pctx->buffer;

    return retval;
}

static __always_inline const char *
compute_pipe(struct csum_context *ctx, struct csum_state *sta, const int pipe)
{
    struct pipe_context pctx;
    const char *result;

    pctx.pipe = pipe;
    sta->pdata = &pctx;
    ctx->next_block = pipe_next_block;
    result = csum_compute(ctx, sta);

    return result;
}

static __always_inline const char *
compute_mmap(struct csum_context *ctx, const void *mmap, size_t size)
{
    struct csum_linear linear;
    const char *result;

    result = csum_linear_compute(ctx, &linear, mmap, size);

    return result;
}

static const char *
do_compute(struct csum_context *ctx, size_t *pactive,
           off_t offset, size_t length)
{
    const char *result;
    size_t active;
    int retval;

    if (!strcmp(optarg, "-")) {
        struct csum_state sta;
        result = compute_pipe(ctx, &sta, STDIN_FILENO);
        active = sta.offset;
    }

    else {
        struct stat stat;
        void *mmaped, *compute;
        int handle;

        if ((handle = open(optarg, O_RDONLY)) < 0)
            err(handle, "failed to open '%s'", optarg);

        if ((retval = fstat(handle, &stat)) < 0)
            err(retval, "failed to fstat '%s'", optarg);

        mmaped = compute = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, handle, 0);
        if (mmaped == MAP_FAILED)
            err(errno, "failed to mmap '%s'", optarg);

        active = stat.st_size;
        if (offset) {
            if (offset > 0) {
                compute += offset;
                active -= offset;
            } else {
                compute += active + offset;
                active = -offset;
            }
        }

        if (length)
            bfdev_min_adj(active, length);
        result = compute_mmap(ctx, compute, active);

        munmap(mmaped, stat.st_size);
        close(handle);
    }

    if (errno || (errno = !result ? EFAULT : 0))
        err(errno, "failed to compute '%s'", optarg);

    *pactive = active;
    return result;
}

static void
print_result(const char *algo, const char *para, size_t active,
             const char *result, unsigned long flags)
{
    if (flags & CSUM_ZERO)
        printf("%s %lld %s", result, (long long)active, optarg);
    else {
        if (para)
            printf("%s [%s]: (%s %lld) = %s\n", algo, para,
                    optarg, (long long)active, result);
        else
            printf("%s: (%s %lld) = %s\n", algo,
                    optarg, (long long)active, result);
    }
}

static __bfdev_noreturn void
usage(void)
{
    struct csum_algo *algo;

    fprintf(stderr, "Usage: csum [OPTION]... [FILE]...\n");
    fprintf(stderr, "Print or verify checksums.\n");
    fprintf(stderr, "By default use the 32 bit CRC algorithm\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "With no FILE, or when FILE is -, read standard input.\n");
    fprintf(stderr, "  -v, --version            output version information and exit.\n");
    fprintf(stderr, "  -h, --help               display this help and exit.\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Mandatory arguments to long options are mandatory for short options too.\n");
    fprintf(stderr, "  -a, --algorithm=TYPE     select the digest type to use.  See DIGEST below.\n");
    fprintf(stderr, "  -p, --parameter=ARGS     algorithm private parameters.\n");
    fprintf(stderr, "  -z, --zero               end each output line with NUL, not newline,\n");
    fprintf(stderr, "                           and disable file name escaping.\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "The following options are only useful when verifying files\n");
    fprintf(stderr, "  -s, --seek=[+][-]OFFSET  start at <OFFSET> bytes abs. (or +: rel.) infile offset.\n");
    fprintf(stderr, "  -l, --len=SIZE           stop after <SIZE> octets.\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "DIGEST determines the digest algorithm and default output format:\n");
    bfdev_list_for_each_entry(algo, &csum_algos, list) {
        if (algo->desc)
            fprintf(stderr, "  %-16s - %s\n", algo->name, algo->desc);
        else
            fprintf(stderr, "  %s\n", algo->name);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "When checking, the input should be a former output of this program,\n");
    fprintf(stderr, "or equivalent standalone program.");
    fprintf(stderr, "\n");

    exit(1);
}

static __bfdev_noreturn void
version(void)
{
    fprintf(stderr, "csum v%d.%d\n", VERSION_MAJOR, VERSION_MINOR);
    fprintf(stderr, "Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>\n");
    fprintf(stderr, "License GPLv2+: GNU GPL version 2 or later.\n");
    exit(1);
}

int main(int argc, char * const argv[])
{
    const char *para = NULL, *algo = DEF_ALGO;
    struct csum_context *ctx = NULL;
    unsigned long flags = 0;
    size_t length = 0;
    off_t offset = 0;
    int optidx;
    char arg;

    while ((arg = getopt_long(argc, argv, "-a:p:zs:l:vh", options, &optidx)) >= 0) {
        switch (arg) {
            case 'a':
                algo = optarg;
                break;

            case 'p':
                para = optarg;
                break;

            case 'z':
                flags |= CSUM_ZERO;
                break;

            case 's':
                offset = (off_t)strtoll(optarg, NULL, 0);
                break;

            case 'l':
                length = (size_t)strtoull(optarg, NULL, 0);
                break;

            case 'v':
                version();

            case 'h': default:
                usage();

            compute: case '\1': {
                const char *result;
                size_t active;

                ctx = csum_prepare(algo, para, 0);
                if (!ctx)
                    usage();

                result = do_compute(ctx, &active, offset, length);
                print_result(algo, para, active, result, flags);
                csum_destroy(ctx);
                break;
            }
        }
    }

    if (!ctx) {
        optarg = "-";
        goto compute;
    }

    return 0;
}
