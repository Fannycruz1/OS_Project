#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdatomic.h>

#include "hash_functions.h"

#define MAX_WORKERS 12

/* functions */

static int next_pow2(int x) {
    int p = 1;
    while (p < x) p <<= 1;
    return p;
}



typedef struct { 
    uint64_t prefix; 
    unsigned char *digest; 
} Bucket;

static void build_mask(unsigned char **digests, int n, int dsz, int *mask) {
    if (n == 0) return;

    int cap = next_pow2(n * 2);
    int mod = cap - 1;

    Bucket *table = calloc(cap, sizeof(Bucket));
    assert(table != NULL);

    for (int i = 0; i < n; i++) {
        uint64_t pfx;
        memcpy(&pfx, digests[i], sizeof pfx);

        int slot = (int)(pfx & (uint64_t)mod);

        for (;;) {
            if (!table[slot].digest) {
                table[slot].prefix = pfx;
                table[slot].digest = digests[i];
                break;
            }

            if (table[slot].prefix == pfx &&
                !memcmp(table[slot].digest, digests[i], dsz)) {
                mask[i] = 1;
                break;
            }

            slot = (slot + 1) & mod;
        }
    }

    free(table);
}

/*  hashing */

typedef struct {
    unsigned char  *file_data;
    unsigned char **digest_ptrs;
    unsigned char  *digest_pool;
    int             digest_size;
    int             chunk_size;
    int             begin;
    int             end;
} DigestRange;

static void *digest_worker(void *arg) {
    DigestRange *r = (DigestRange *)arg;

    int cs = r->chunk_size;
    int ds = r->digest_size;

    for (int i = r->begin; i < r->end; i++) {
        unsigned char *h = calculate_sha512(
            r->file_data + (size_t)i * cs, cs);

        unsigned char *slot = r->digest_pool + (size_t)i * ds;

        memcpy(slot, h, ds);
        free(h);

        r->digest_ptrs[i] = slot;
    }

    return NULL;
}



void dedupe(char *filename, int chunk_size, char *output) {
    FILE *fp = fopen(filename, "r");
    assert(fp != NULL);

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    int n = 0;
    if (fsize >= chunk_size) {
        n = (int)(fsize / chunk_size);
    }

    unsigned char *raw = NULL;

    if (n > 0) {
        raw = malloc((size_t)n * chunk_size);
        assert(raw != NULL);

        n = (int)fread(raw, chunk_size, n, fp);
    }

    fclose(fp);

    int dsz = (int)size_sha512();

    unsigned char **digests = NULL;
    unsigned char  *dpool   = NULL;

    if (n > 0) {
        digests = malloc((size_t)n * sizeof(unsigned char *));
        dpool   = malloc((size_t)n * dsz);

        assert(digests != NULL);
        assert(dpool   != NULL);
    }

    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;

    int nw = (int)ncpus;

    if (nw > MAX_WORKERS) {
        nw = MAX_WORKERS;
    }

    if (nw > n) {
        nw = n;
    }

    DigestRange ranges[MAX_WORKERS];
    pthread_t   tids[MAX_WORKERS];

    for (int t = 0; t < nw; t++) {
        ranges[t].file_data   = raw;
        ranges[t].digest_ptrs = digests;
        ranges[t].digest_pool = dpool;
        ranges[t].digest_size = dsz;
        ranges[t].chunk_size  = chunk_size;

        ranges[t].begin = (int)((long)t * n / nw);
        ranges[t].end   = (int)((long)(t + 1) * n / nw);

        pthread_create(&tids[t], NULL, digest_worker, &ranges[t]);
    }

    for (int t = 0; t < nw; t++) {
        pthread_join(tids[t], NULL);
    }

    free(raw);

    int *mask = calloc(n > 0 ? n : 1, sizeof(int));
    assert(mask != NULL);

    build_mask(digests, n, dsz, mask);

    fp = fopen(output, "w");
    assert(fp != NULL);

    if (n > 0) {
        char *outbuf = malloc(n + 1);
        assert(outbuf != NULL);

        for (int i = 0; i < n; i++) {
            outbuf[i] = '0' + mask[i];
        }

        outbuf[n] = '\n';

        fwrite(outbuf, 1, n + 1, fp);
        free(outbuf);
    } else {
        fputc('\n', fp);
    }

    fclose(fp);

    free(mask);
    free(dpool);
    free(digests);
}
