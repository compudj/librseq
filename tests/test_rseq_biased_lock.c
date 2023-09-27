// SPDX-License-Identifier: LGPL-2.1

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>
#include <syscall.h>
#include <inttypes.h>
#include <linux/version.h>
#include <linux/membarrier.h>

#include <rseq/rseq.h>
#include "rseq_biased_lock.h"

#define NR_THREADS	5
#define NR_REPS		5000

static int opt_threads = NR_THREADS;
static int opt_bias = 0;
static uint64_t opt_reps = NR_REPS;

static DEFINE_RSEQ_BIASED_LOCK(test_lock);

static int testvar;

static
void *test_thread(void *arg)
{
	int thread_nr = (int)(intptr_t)arg;
	uint64_t i;

	printf("Thread %d start\n", thread_nr);

	if (rseq_register_current_thread()) {
		fprintf(stderr, "Error: rseq_register_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		abort();
	}

	if (thread_nr == opt_bias) {
		if (rseq_biased_lock_try_set_fast_thread(&test_lock)) {
			fprintf(stderr, "Error: biased lock fast thread already set.\n");
			abort();
		}
	}
	for (i = 0; i < opt_reps; i++) {
		int var;

		rseq_biased_lock(&test_lock);
		var = RSEQ_READ_ONCE(testvar);
		if (var) {
			fprintf(stderr, "Unexpected value %d\n", var);
			abort();
		}
		RSEQ_WRITE_ONCE(testvar, 1);
		RSEQ_WRITE_ONCE(testvar, 0);
		rseq_biased_unlock(&test_lock);
	}

	if (thread_nr == opt_bias) {
		if (rseq_biased_lock_try_clear_fast_thread(&test_lock)) {
			fprintf(stderr, "Error: biased lock fast thread already cleared.\n");
			abort();
		}
	}

	printf("Thread %d exit\n", thread_nr);

	if (rseq_unregister_current_thread()) {
		fprintf(stderr, "Error: rseq_unregister_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		abort();
	}
	return NULL;
}

static void show_usage(char **argv)
{
	printf("Usage : %s <OPTIONS>\n",
		argv[0]);
	printf("OPTIONS:\n");
	printf("	[-t N] Number of threads (default 5)\n");
	printf("	[-b N] Thread number to use as fast locking bias (-1: none) (default 0)\n");
	printf("	[-r N] Number of repetitions per thread (default 5000)\n");
	printf("	[-h] Show this help.\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	pthread_t *test_thread_id;
	int i, ret;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-')
			continue;
		switch (argv[i][1]) {
		case 't':
			if (argc < i + 2) {
				show_usage(argv);
				goto error;
			}
			opt_threads = atol(argv[i + 1]);
			if (opt_threads < 0) {
				show_usage(argv);
				goto error;
			}
			i++;
			break;
		case 'b':
			if (argc < i + 2) {
				show_usage(argv);
				goto error;
			}
			opt_bias = atol(argv[i + 1]);
			if (opt_bias < -1) {
				show_usage(argv);
				goto error;
			}
			i++;
			break;

		case 'r':
		{
			long long reps;

			if (argc < i + 2) {
				show_usage(argv);
				goto error;
			}
			reps = atoll(argv[i + 1]);
			if (reps < 0) {
				show_usage(argv);
				goto error;
			}
			opt_reps = (uint64_t) reps;
			i++;
			break;
		}
		case 'h':
			show_usage(argv);
			goto end;
		default:
			show_usage(argv);
			goto error;
		}
	}
	printf("Test biased lock. opt_threads=%d, opt_bias=%d, opt_reps=%" PRIu64 "\n",
		opt_threads, opt_bias, opt_reps);
	if (!membarrier_private_expedited_rseq_available()) {
		fprintf(stderr, "Membarrier private expedited rseq not available. "
				"Skipping biased lock test.\n");
		return -1;
	}
	if (sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 0)) {
		perror("sys_membarrier");
		abort();
	}
	test_thread_id = calloc(opt_threads, sizeof(test_thread_id[0]));
	if (!test_thread_id)
		abort();

	for (i = 0; i < opt_threads; i++) {
		ret = pthread_create(&test_thread_id[i], NULL, test_thread, (void *)(intptr_t)i);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			abort();
		}
	}

	for (i = 0; i < opt_threads; i++) {
		ret = pthread_join(test_thread_id[i], NULL);
		if (ret) {
			errno = ret;
			perror("pthread_join");
			abort();
		}
	}
	free(test_thread_id);
end:
	return 0;
error:
	return -1;
}
