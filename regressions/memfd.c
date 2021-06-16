#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "bcd.h"

/* Default size of buffer. */
#define BUFFER_SIZE	4096

/* This descriptor is shared between the child and parent. */
static int buffer_fd;

/* This is the pointer to the buffer used by the BCD child. */
static char *buffer_child;

static void *
buffer_reader(int fd, int flags)
{
	void *r;

	r = mmap(NULL, BUFFER_SIZE, flags, MAP_SHARED, fd, 0);
	if (r == MAP_FAILED)
		abort();

	return r;
}

static void *
buffer_create(void)
{
	void *r;
	int fd;

	fd = memfd_create("_backtrace_buffer", MFD_CLOEXEC);
	if (fd == -1)
		abort();

	if (ftruncate(fd, BUFFER_SIZE) == -1)
		abort();

	buffer_fd = fd;

	r = buffer_reader(buffer_fd, PROT_READ);

	fprintf(stderr, "%ju: Returned pointer: %p (buffer_child = %p)\n",
	    (uintmax_t)getpid(), r, buffer_child);

	return r;
}

static int
request_handler(pid_t tid)
{
	time_t now = time(NULL);

	/* We write data to the buffer. */
	sprintf(buffer_child, "A new requested generated at: %ju",
	    (uintmax_t)now);

	/* We return -1 to tell BCD it only needs to execute this function. */
	return -1;
}

static void
monitor_init(void)
{

	fprintf(stderr, "Child is %ju\n", (uintmax_t)getpid());

	if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) == -1)
		perror("prctl");

	/*
	 * This is called after the parent process has set buffer_fd. Set
	 * a memory mapping to the same descriptor.
	 */
	buffer_child = buffer_reader(buffer_fd, PROT_READ | PROT_WRITE);
	if (buffer_child == NULL)
		abort();

	sprintf(buffer_child, "Empty contents.");
	fprintf(stderr, "%ju: Returned pointer: %p (buffer_child = %p)\n",
	    (uintmax_t)getpid(), buffer_child, buffer_child);
	return;
}

int
main(void)
{
	struct bcd_config cf;
	bcd_t bcd;
	bcd_error_t e;
	const char *buffer;

	/* Initialize a shared memory region. */
	buffer = buffer_create();

	/* Initialize the BCD configuration file. */
	if (bcd_config_init(&cf, &e) == -1)
		abort();

	/* Request handler to be called when processing errors by BCD worker. */
	cf.request_handler = request_handler;

	/* Set a function to be called by the child for setting permissions. */
	cf.monitor_init = monitor_init;

	if (bcd_init(&cf, &e) == -1) {
		fprintf(stderr, "error: failed to init: %s (%s)\n",
		    e.message, strerror(e.errnum));
		abort();
	}

	/* Initialize the BCD handler. */
	if (bcd_attach(&bcd, &e) == -1)
		abort();

	/* Generate a backtrace. This is executed synchronously. */
	bcd_emit(&bcd, "1");
	printf("%ju: Buffer contents: %s\n", (uintmax_t)getpid(), buffer);

	sleep(2);

	/* Execute another. */
	bcd_emit(&bcd, "2");
	printf("%ju: Buffer contents: %s\n", (uintmax_t)getpid(), buffer);
	return 0;
}
