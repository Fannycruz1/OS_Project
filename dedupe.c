/*
 * dedupe.c  —  parallel implementation
 *
 * Optimizations over the reference serial version:
 *
 *  1. Read entire file in one fread() instead of chunk-by-chunk.
 *
 *  2. Hash all chunks in parallel using NUM_THREADS worker threads.
 *     Work is statically partitioned (no mutex hot-path during hashing).
 *     Each thread holds its own local copy of the chunk data because
 *     calculate_sha512() sorts the buffer in-place via qsort().
 *
 *  3. Duplicate detection via open-addressing hash map -> O(n) instead of
 *     the reference's O(n^2) nested loop. This matters enormously on large
 *     files with small chunk sizes (e.g., 100 MB / 4 B = 25 M chunks).
 *
 *  4. Output written in one fwrite() call instead of n_chunks fprintf() calls.
 *
 * Thread budget: NUM_THREADS worker threads + 1 main thread = 12 total,
 * which is exactly the allowed maximum.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <sys/stat.h>

#include "hash_functions.h"

/* tuneable */
#define NUM_THREADS 11   /* +1 main = 12 total (hard cap per spec) */

/* ---- parallel hashing -------------------------------------------------- */

typedef struct {
    const char    *file_data;   /* read-only pointer into the file buffer */
    int            chunk_size;
    int            start;       /* first chunk index owned by this thread */
    int            end;         /* one past last chunk index (exclusive)  */
    unsigned char **hashes;     /* shared output array; each slot is independent */
} HashArg;

static void *hash_worker(void *arg)
{
    const HashArg *a = (const HashArg *)arg;

    /*
     * Local buffer: calculate_sha512() sorts its input in-place (qsort),
     * so we must not pass a pointer into the shared file buffer.
     * One local copy per thread, reused across all chunks this thread owns.
     */
    unsigned char *local_buf = (unsigned char *)malloc(a->chunk_size);
    assert(local_buf);

    for (int i = a->start; i < a->end; i++) {
        memcpy(local_buf, a->file_data + (long)i * a->chunk_size, a->chunk_size);
        a->hashes[i] = calculate_sha512(local_buf, a->chunk_size);
    }

    free(local_buf);
    return NULL;
}

/* ---- open-addressing hash map ------------------------------------------
 *
 * Key   : pointer to a SHA-512 hash (64 bytes), compared with memcmp.
 * Value : implicit -- presence means "seen at least once".
 *
 * Initial slot = first 4 bytes of SHA-512 output (uniformly distributed).
 * Load factor kept <= 50% (capacity = next power-of-2 >= 2*n_chunks).
 * ------------------------------------------------------------------------ */

typedef struct { unsigned char *hash; } Slot;

static int ht_insert_or_find(Slot *ht, unsigned int cap_mask,
                              unsigned char *hash, int hash_size)
{
    unsigned int s = ((unsigned int)hash[0] << 24)
                   | ((unsigned int)hash[1] << 16)
                   | ((unsigned int)hash[2] <<  8)
                   |  (unsigned int)hash[3];
    s &= cap_mask;

    while (ht[s].hash != NULL) {
        if (memcmp(ht[s].hash, hash, hash_size) == 0)
            return 1;            /* duplicate */
        s = (s + 1) & cap_mask; /* linear probe */
    }
    ht[s].hash = hash;
    return 0;                    /* newly inserted */
}

/* keep compare_hashes() in case anything links against it */
int compare_hashes(unsigned char *a, unsigned char *b, int n)
{
    for (int i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

/* ---- main entry point -------------------------------------------------- */

void dedupe(char *filename, int chunk_size, char *output)
{
    /* 1. Read entire file into one contiguous buffer */
    FILE *fp = fopen(filename, "r");
    assert(fp != NULL);

    struct stat st;
    fstat(fileno(fp), &st);
    long file_size = st.st_size;

    /*
     * The reference ignores any trailing partial chunk
     * (fread returns < chunk_size -> loop ends).
     * Equivalent: integer division.
     */
    int n_chunks = (int)(file_size / chunk_size);

    char *file_data = NULL;
    if (n_chunks > 0) {
        long needed = (long)n_chunks * chunk_size;
        file_data = (char *)malloc(needed);
        assert(file_data);
        size_t rd = fread(file_data, 1, needed, fp);
        (void)rd;
    }
    fclose(fp);

    /* Edge case: no complete chunks -> output is just a newline (matches ref). */
    if (n_chunks == 0) {
        fp = fopen(output, "w");
        assert(fp);
        fprintf(fp, "\n");
        fclose(fp);
        free(file_data);
        return;
    }

    /* 2. Allocate the hash pointer array */
    int hash_size = size_sha512();
    unsigned char **hashes =
        (unsigned char **)malloc(n_chunks * sizeof(unsigned char *));
    assert(hashes);

    /* 3. Hash all chunks in parallel
     *
     * Static partitioning: thread t owns chunks [start_t, end_t).
     * No mutexes needed -- each slot in `hashes` is written by exactly one thread.
     */
    int nthreads = (NUM_THREADS < n_chunks) ? NUM_THREADS : n_chunks;

    pthread_t tids[NUM_THREADS];
    HashArg   args[NUM_THREADS];

    int base  = n_chunks / nthreads;
    int extra = n_chunks % nthreads;  /* first `extra` threads get one extra chunk */
    int cur   = 0;

    for (int t = 0; t < nthreads; t++) {
        int count          = base + (t < extra ? 1 : 0);
        args[t].file_data  = file_data;
        args[t].chunk_size = chunk_size;
        args[t].start      = cur;
        args[t].end        = cur + count;
        args[t].hashes     = hashes;
        cur += count;
        pthread_create(&tids[t], NULL, hash_worker, &args[t]);
    }
    for (int t = 0; t < nthreads; t++)
        pthread_join(tids[t], NULL);

    /* file_data no longer needed -- free before allocating the hash table */
    free(file_data);

    /* 4. Find duplicates via O(n) hash map
     *
     * For each chunk i (in order), check whether its hash was already seen.
     *   Yes -> mask[i] = 1  (duplicate of some earlier chunk j < i)
     *   No  -> mask[i] = 0, and record this hash as first occurrence.
     *
     * This matches the reference semantics exactly:
     *   mask[j] = 1  iff  exists i < j  s.t.  hashes[i] == hashes[j]
     *
     * Capacity: next power-of-2 >= 2*n_chunks -> load factor <= 50%.
     */
    unsigned int cap = 1;
    while (cap < (unsigned int)(2 * n_chunks)) cap <<= 1;
    unsigned int cap_mask = cap - 1;

    Slot *ht = (Slot *)calloc(cap, sizeof(Slot));
    assert(ht);

    /* Reuse hashes[i] pointer as the table key -- no extra copy needed. */
    char *mask = (char *)malloc(n_chunks + 2); /* '0'/'1' chars + '\n' + NUL */
    assert(mask);

    for (int i = 0; i < n_chunks; i++)
        mask[i] = '0' + ht_insert_or_find(ht, cap_mask, hashes[i], hash_size);

    free(ht);

    /* 5. Write output in one shot
     *
     * n_chunks individual fprintf() calls are slow for large n.
     * Build the result in-memory and fwrite it all at once.
     */
    mask[n_chunks]     = '\n';
    mask[n_chunks + 1] = '\0';

    fp = fopen(output, "w");
    assert(fp != NULL);
    fwrite(mask, 1, n_chunks + 1, fp);
    fclose(fp);

    /* 6. Release memory */
    free(mask);
    for (int i = 0; i < n_chunks; i++)
        free(hashes[i]);
    free(hashes);
}
