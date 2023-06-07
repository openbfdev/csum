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
#include <bfdev/minmax.h>
#include <bfdev/attributes.h>

#define DEF_ALGO "crc32"
#define PIPE_BUFFER 0x10000

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

static __noreturn void usage(void)
{
    struct csum_algo *algo;

    fprintf(stderr, "Usage: csum [options]... [source]...\n");
    fprintf(stderr, "Print or verify checksums.\n");
    fprintf(stderr, "By default use the 32 bit CRC algorithm\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "With no source, or when source is -, read standard input.\n");
    fprintf(stderr, "  -v, --version            output version information and exit\n");
    fprintf(stderr, "  -h, --help               display this help and exit\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Mandatory arguments to long options are mandatory for short options too.\n");
    fprintf(stderr, "  -a, --algorithm=TYPE     select the digest type to use.  See DIGEST below.\n");
    fprintf(stderr, "  -p, --parameter=ARGS     algorithm private parameters.\n");
    fprintf(stderr, "  -z, --zero               end each output line with NUL, not newline,\n");
    fprintf(stderr, "                           and disable source name escaping\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "The following options are only useful when verifying files\n");
    fprintf(stderr, "  -s, --seek=[+][-]OFFSET  start at <OFFSET> bytes abs. (or +: rel.) infile offset.\n");
    fprintf(stderr, "  -l, --len=SIZE           stop after <SIZE> octets\n");
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

static __noreturn void version(void)
{
    fprintf(stderr, "csum v%d.%d\n", VERSION_MAJOR, VERSION_MINOR);
    fprintf(stderr, "Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>\n");
    fprintf(stderr, "License GPLv2+: GNU GPL version 2 or later.\n");
    exit(1);
}

int main(int argc, char * const argv[])
{
    const char *algo = DEF_ALGO, *para = NULL;
    struct csum_context *ctx;
    unsigned int index;
    int optidx, retval;
    bool zero = false;
    off_t offset = 0;
    size_t length = 0;
    char arg;

    while ((arg = getopt_long(argc, argv, "a:p:zs:l:vh", options, &optidx)) != -1) {
        switch (arg) {
            case 'a':
                algo = optarg;
                break;

            case 'p':
                para = optarg;
                break;

            case 'z':
                zero = true;
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
        }
    }

    for (index = 0; index + optind <= argc; ++index) {
        const char *result, *source = argv[optind + index];
        size_t active;

        ctx = csum_prepare(algo, para, 0);
        if (!ctx)
            usage();

        if (source ? !strcmp(source, "-") : !index) {
            struct csum_state sta;
            result = compute_pipe(ctx, &sta, STDIN_FILENO);
            active = sta.offset;
            source = "-";
        }

        else if (!source)
            break;

        else {
            struct stat stat;
            void *mmaped, *compute;
            int handle;

            if ((handle = open(source, O_RDONLY)) < 0)
                err(handle, "failed to open '%s'", source);

            if ((retval = fstat(handle, &stat)) < 0)
                err(retval, "failed to fstat '%s'", source);

            mmaped = compute = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, handle, 0);
            if (mmaped == MAP_FAILED)
                err(errno, "failed to mmap '%s'", source);

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
            err(errno, "failed to compute '%s'", source);

        if (zero)
            printf("%s %lld %s", result, (long long)active, source);
        else {
            if (para)
                printf("%s [%s]: (%s %lld) = %s\n", algo, para,
                        source, (long long)active, result);
            else
                printf("%s: (%s %lld) = %s\n", algo,
                        source, (long long)active, result);
        }

        csum_destroy(ctx);
    }

    return retval;
}
