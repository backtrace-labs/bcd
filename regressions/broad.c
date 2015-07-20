#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bcd.h"

#ifndef NTHR
#define NTHR 3
#endif /* NTHR */

static pthread_t threads[NTHR];

static void *
broad_thread(void *unused)
{
	bcd_t bcd;
	bcd_error_t error;
	static __thread int test;
	char buffer[128];
	int i = 0;

	(void)unused;

	if (bcd_attach(&bcd, &error) == -1) {
		fprintf(stderr, "error: failed to attach: %s (%s)\n",
		    error.message, strerror(error.errnum));
		return NULL;
	}

	test = 31337 + (uintptr_t)&test;
	sprintf(buffer, "%p %d", (void *)&test, i++);
	bcd_kv(&bcd, "thread_1", buffer, &error);
	bcd_emit(&bcd, "this is a test...omg");
	bcd_kv(&bcd, "thread_1", buffer, &error);

	if (bcd_detach(&bcd, &error) == -1) {
		fprintf(stderr, "error: failed to detach: %s (%s)\n",
		    error.message, strerror(error.errnum));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr,"exit\n");
	return NULL;
}

int
main(void)
{
	bcd_t bcd;
	bcd_error_t e;
	size_t i;

	struct bcd_config cf;
	if (bcd_config_init(&cf, &e) == -1) {
		fprintf(stderr, "error: failed to init config: %s (%s)\n",
		    e.message, strerror(e.errnum));
		exit(EXIT_FAILURE);
	}

	cf.invoke.kp = NULL;
	cf.invoke.tp = NULL;
	cf.invoke.output_file = "bcd_output_file";

	if (bcd_init(&cf, &e) == -1) {
		fprintf(stderr, "error: failed to init: %s (%s)\n",
		    e.message, strerror(e.errnum));
		exit(EXIT_FAILURE);
	}

	if (bcd_attach(&bcd, &e) == -1) {
		fprintf(stderr, "error: failed to attach: %s (%s)\n",
		    e.message, strerror(e.errnum));
		exit(EXIT_FAILURE);
	}

	bcd_kv(&bcd, "thread", "poop", &e);
	bcd_kv(&bcd, "version", "8.3.2", &e);

	bcd_backtrace(&bcd, BCD_TARGET_PROCESS, &e);

	for (i = 0; i < NTHR; i++)
		pthread_create(&threads[i], NULL, broad_thread, NULL);

	for (i = 0; i < NTHR; i++)
		pthread_join(threads[i], NULL);

	sleep(1);
	bcd_fatal("test");
	return 0;
}
