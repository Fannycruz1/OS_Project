#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>

#include "hash_functions.h"

#define MAX_THREADS 10
#define QUEUE_CAPACITY 128  


_Atomic int shared_current_i = 0;

typedef struct {
	char *data;
	int index;
	unsigned char *hash;
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

typedef struct {
	unsigned char **hashes;
	_Atomic int *mask;
	int hash_size;
	int n_hashes;
} compare_thread_data_t;


int verify_hash_byte_equality(unsigned char *a, unsigned char *b, int n) {
	return memcmp(a, b, n) == 0;
}

work_queue_t* initialize_threaded_work_queue(int capacity) {
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

void cleanup_threaded_work_queue(work_queue_t *q) {
	pthread_mutex_destroy(&q->mutex);
	pthread_cond_destroy(&q->not_empty);
	pthread_cond_destroy(&q->not_full);
	free(q->queue);
	free(q);
}

void add_work_item_to_queue(work_queue_t *q, work_item_t item) {
	pthread_mutex_lock(&q->mutex);
	while(q->size == q->capacity) {
		pthread_cond_wait(&q->not_full, &q->mutex);
	}
	q->queue[q->rear] = item;
	q->rear = (q->rear + 1) % q->capacity;
	q->size++;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->mutex);
}

int retrieve_work_item_from_queue(work_queue_t *q, work_item_t *item) {
	pthread_mutex_lock(&q->mutex);
	while(q->size == 0 && !q->done) {
		pthread_cond_wait(&q->not_empty, &q->mutex);
	}
	if(q->size == 0 && q->done) {
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

void signal_work_queue_completion(work_queue_t *q) {
	pthread_mutex_lock(&q->mutex);
	q->done = 1;
	pthread_cond_broadcast(&q->not_empty);
	pthread_mutex_unlock(&q->mutex);
}

void* process_hash_calculation_thread(void *arg) {
	hash_thread_data_t *data = (hash_thread_data_t *)arg;
	work_item_t item;

	while(retrieve_work_item_from_queue(data->queue, &item)) {
		data->hashes[item.index] = calculate_sha512((unsigned char *)item.data, data->chunk_size);
		free(item.data);
	}
	return NULL;
}

void* execute_duplicate_comparison_thread(void *arg) {
	compare_thread_data_t *data = (compare_thread_data_t *)arg;
	while (1) {
		int i = atomic_fetch_add(&shared_current_i, 1);
		if (i >= data->n_hashes) break;

		if (atomic_load(&data->mask[i])) continue;

		for(int j = i + 1; j < data->n_hashes; j++) {
			if(verify_hash_byte_equality(data->hashes[i], data->hashes[j], data->hash_size)) {
				atomic_store(&data->mask[j], 1);
			}
		}
	}
	return NULL;
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

	if(n_hashes == 0) {
		fp = fopen(output, "w");
		fprintf(fp, "\n");
		fclose(fp);
		return;
	}

	unsigned char **hashes = malloc(n_hashes * sizeof(unsigned char *));
	assert(hashes != NULL);
	for(int i = 0; i < n_hashes; i++) hashes[i] = NULL;

	work_queue_t *queue = initialize_threaded_work_queue(QUEUE_CAPACITY);
	hash_thread_data_t hash_data = {queue, hashes, chunk_size};

	int num_threads = (n_hashes < MAX_THREADS) ? n_hashes : MAX_THREADS;
	pthread_t hash_threads[MAX_THREADS];

	for(int i = 0; i < num_threads; i++) {
		pthread_create(&hash_threads[i], NULL, process_hash_calculation_thread, &hash_data);
	}

	fp = fopen(filename, "r");
	assert(fp != NULL);
	for(int i = 0; i < n_hashes; i++) {
		char *chunk_data = malloc(chunk_size);
		assert(chunk_data != NULL);
		if (fread(chunk_data, sizeof(char), chunk_size, fp) != (size_t)chunk_size) {
			free(chunk_data);
			break;
		}
		work_item_t item = {chunk_data, i, NULL};
		add_work_item_to_queue(queue, item);
	}
	fclose(fp);

	signal_work_queue_completion(queue);

	for(int i = 0; i < num_threads; i++) {
		pthread_join(hash_threads[i], NULL);
	}

	cleanup_threaded_work_queue(queue);

	atomic_store(&shared_current_i, 0);

	_Atomic int *mask = calloc(n_hashes, sizeof(_Atomic int));

	pthread_t compare_threads[MAX_THREADS];
	compare_thread_data_t compare_data[MAX_THREADS];
	int threads_used = (n_hashes < MAX_THREADS) ? n_hashes : MAX_THREADS;

	for(int i = 0; i < threads_used; i++) {
		compare_data[i].hashes = hashes;
		compare_data[i].mask = mask;
		compare_data[i].hash_size = hash_size;
		compare_data[i].n_hashes = n_hashes;
		pthread_create(&compare_threads[i], NULL, execute_duplicate_comparison_thread, &compare_data[i]);
	}

	for(int i = 0; i < threads_used; i++) {
		pthread_join(compare_threads[i], NULL);
	}

	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashes; i++)
		fprintf(fp, "%d", mask[i]);
	fprintf(fp, "\n");
	fclose(fp);

	for(int i=0; i < n_hashes; i++)
		free(hashes[i]);
	free(hashes);
	free(mask);
}
