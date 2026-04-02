#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>

#include "hash_functions.h"

#define MAX_THREADS 11
#define QUEUE_CAPACITY 128


typedef struct {
	char *data;
	int index;
} work_item_t;

typedef struct {
	work_item_t *queue;
	int front, rear, size, capacity;
	pthread_mutex_t mutex;
	pthread_cond_t not_empty, not_full;
	int done;
} work_queue_t;

typedef struct {
	work_queue_t *queue;
	unsigned char **hashes;
	int chunk_size;
} hash_thread_data_t;

work_queue_t* init_queue(int capacity) {
	work_queue_t *q = malloc(sizeof(work_queue_t));
	q->queue = malloc(capacity * sizeof(work_item_t));
	q->front = q->rear = q->size = 0;
	q->capacity = capacity;
	q->done = 0;
	pthread_mutex_init(&q->mutex, NULL);
	pthread_cond_init(&q->not_empty, NULL);
	pthread_cond_init(&q->not_full, NULL);
	return q;
}

void destroy_queue(work_queue_t *q) {
	pthread_mutex_destroy(&q->mutex);
	pthread_cond_destroy(&q->not_empty);
	pthread_cond_destroy(&q->not_full);
	free(q->queue);
	free(q);
}

void enqueue(work_queue_t *q, work_item_t item) {
	pthread_mutex_lock(&q->mutex);
	while (q->size == q->capacity)
		pthread_cond_wait(&q->not_full, &q->mutex);
	q->queue[q->rear] = item;
	q->rear = (q->rear + 1) % q->capacity;
	q->size++;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->mutex);
}

int dequeue(work_queue_t *q, work_item_t *item) {
	pthread_mutex_lock(&q->mutex);
	while (q->size == 0 && !q->done)
		pthread_cond_wait(&q->not_empty, &q->mutex);
	if (q->size == 0 && q->done) {
		pthread_mutex_unlock(&q->mutex);
		return 0;
	}
	*item = q->queue[q->front];
	q->front = (q->front + 1) % q->capacity;
	q->size--;
	pthread_cond_signal(&q->not_full);
	pthread_mutex_unlock(&q->mutex);
	return 1;
}

void queue_done(work_queue_t *q) {
	pthread_mutex_lock(&q->mutex);
	q->done = 1;
	pthread_cond_broadcast(&q->not_empty);
	pthread_mutex_unlock(&q->mutex);
}


void* hash_worker(void *arg) {
	hash_thread_data_t *data = (hash_thread_data_t *)arg;
	work_item_t item;
	while (dequeue(data->queue, &item)) {
		data->hashes[item.index] = calculate_sha512((unsigned char *)item.data, data->chunk_size);
		free(item.data);
	}
	return NULL;
}


#define HT_SIZE (1 << 20)
#define HT_MASK (HT_SIZE - 1)

typedef struct ht_entry {
	unsigned char *key;
	int first_index;
	struct ht_entry *next;
} ht_entry_t;

typedef struct {
	ht_entry_t **buckets;
	int hash_size;
} hash_table_t;

hash_table_t* ht_create(int hash_size) {
	hash_table_t *ht = malloc(sizeof(hash_table_t));
	ht->buckets = calloc(HT_SIZE, sizeof(ht_entry_t *));
	ht->hash_size = hash_size;
	return ht;
}

void ht_destroy(hash_table_t *ht) {
	for (int i = 0; i < HT_SIZE; i++) {
		ht_entry_t *e = ht->buckets[i];
		while (e) {
			ht_entry_t *next = e->next;
			free(e);
			e = next;
		}
	}
	free(ht->buckets);
	free(ht);
}

// Use first 4 bytes of SHA-512 as bucket index (already high-entropy)
static inline unsigned int ht_bucket(unsigned char *key) {
	unsigned int h = 0;
	h |= (unsigned int)key[0];
	h |= (unsigned int)key[1] << 8;
	h |= (unsigned int)key[2] << 16;
	h |= (unsigned int)key[3] << 24;
	return h & HT_MASK;
}

// Returns first_index if already seen, else inserts and returns -1
int ht_lookup_or_insert(hash_table_t *ht, unsigned char *key, int index) {
	unsigned int b = ht_bucket(key);
	ht_entry_t *e = ht->buckets[b];
	while (e) {
		if (memcmp(e->key, key, ht->hash_size) == 0)
			return e->first_index;
		e = e->next;
	}
	ht_entry_t *ne = malloc(sizeof(ht_entry_t));
	ne->key = key;
	ne->first_index = index;
	ne->next = ht->buckets[b];
	ht->buckets[b] = ne;
	return -1;
}


void dedupe(char *filename, int chunk_size, char *output) {
	FILE *fp;
	int hash_size = size_sha512();

	fp = fopen(filename, "r");
	assert(fp != NULL);
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fclose(fp);

	int n_hashes = (int)(file_size / chunk_size);

	if (n_hashes == 0) {
		fp = fopen(output, "w");
		fprintf(fp, "\n");
		fclose(fp);
		return;
	}

	unsigned char **hashes = calloc(n_hashes, sizeof(unsigned char *));
	assert(hashes != NULL);

	// Phase 1: parallel hashing with 11 threads
	work_queue_t *queue = init_queue(QUEUE_CAPACITY);
	hash_thread_data_t hash_data = {queue, hashes, chunk_size};

	int num_threads = (n_hashes < MAX_THREADS) ? n_hashes : MAX_THREADS;
	pthread_t hash_threads[MAX_THREADS];
	for (int i = 0; i < num_threads; i++)
		pthread_create(&hash_threads[i], NULL, hash_worker, &hash_data);

	fp = fopen(filename, "r");
	assert(fp != NULL);
	for (int i = 0; i < n_hashes; i++) {
		char *chunk = malloc(chunk_size);
		assert(chunk != NULL);
		if (fread(chunk, 1, chunk_size, fp) != (size_t)chunk_size) {
			free(chunk);
			break;
		}
		work_item_t item = {chunk, i};
		enqueue(queue, item);
	}
	fclose(fp);

	queue_done(queue);
	for (int i = 0; i < num_threads; i++)
		pthread_join(hash_threads[i], NULL);
	destroy_queue(queue);

	// Phase 2: O(n) duplicate detection via hash table — single pass, no threads needed
	int *mask = calloc(n_hashes, sizeof(int));
	hash_table_t *ht = ht_create(hash_size);

	for (int i = 0; i < n_hashes; i++) {
		if (ht_lookup_or_insert(ht, hashes[i], i) != -1)
			mask[i] = 1;
	}

	ht_destroy(ht);

	fp = fopen(output, "w");
	assert(fp != NULL);
	for (int i = 0; i < n_hashes; i++)
		fprintf(fp, "%d", mask[i]);
	fprintf(fp, "\n");
	fclose(fp);

	for (int i = 0; i < n_hashes; i++)
		free(hashes[i]);
	free(hashes);
	free(mask);
}
