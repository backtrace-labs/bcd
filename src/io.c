#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#ifndef BCD_IO_NEVENT
#define BCD_IO_NEVENT 128
#endif /* BCD_IO_NEVENT */

static TAILQ_HEAD(, bcd_io_event) readyevents =
    TAILQ_HEAD_INITIALIZER(readyevents);

struct bcd_io_listener {
	const char *path;
	int fd;
};

struct bcd_io_listener_state {
	bcd_io_listener_handler_t *accept;
	bcd_io_event_handler_t *handler;
	size_t payload;
};

/*
 * Waits until an absolute timeout (timeout_abstime) for an fd to become ready.
 * Behavior for timeout_abstime values is as follows:
 *  timeout_abstime > 0 - Wait until the bcd_os_time() meets or exceeds the
 *     specified value.
 *  timeout_abstime == 0 - Wait forever.
 *  timeout_abstime < 0 - Return immediately.
 * The underlying implementation computes the relative value needed by select()
 * as close as possible to the select() call as well as bounding it to no more
 * than bcd_config.timeout to minimize risk of extended delays due to the clock
 * shifting underneath us.  However, any relative timeout syscall will always be
 * subject to such risks.
 */
int
bcd_io_fd_wait(int fd, enum bcd_io_fd_wait wt, time_t timeout_abstime)
{
	struct timeval tv;
	fd_set wfd, errfd;
	int r = 0;

	FD_ZERO(&wfd);
	FD_SET(fd, &wfd);
	FD_ZERO(&errfd);
	FD_SET(fd, &errfd);

	for (;;) {
		time_t now = bcd_os_time();

		if (now >= timeout_abstime)
			tv.tv_sec = 0;
		else if (timeout_abstime - now > bcd_config.timeout)
			tv.tv_sec = bcd_config.timeout;
		else
			tv.tv_sec = timeout_abstime - now;

		tv.tv_usec = 0;

		r = select(FD_SETSIZE, wt == BCD_IO_FD_WAIT_RD ? &wfd : NULL,
		    wt == BCD_IO_FD_WAIT_WR ? &wfd : NULL,
		    &errfd, timeout_abstime == 0 ? NULL : &tv);
		if (r == -1) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		break;
	}

	return r;
}

ssize_t
bcd_io_fd_read(int fd, void *b, size_t n_read, time_t timeout_abstime)
{
	ssize_t ac = 0;
	char *buffer = b;

	for (;;) {
		ssize_t r = read(fd, buffer + ac, n_read - ac);
		if (r == 0)
			return 0;

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				int ret = bcd_io_fd_wait(fd, BCD_IO_FD_WAIT_RD,
				    timeout_abstime);

				if (ret == 1)
					continue;

				errno = EAGAIN;
			}

			return -1;
		}

		ac += r;
		if ((size_t)ac == n_read)
			break;
	}

	return ac;
}

ssize_t
bcd_io_fd_write(int fd, const void *b, size_t n_write, time_t timeout_abstime)
{
	ssize_t ac = 0;
	const char *buffer = b;

	for (;;) {
		ssize_t r = write(fd, buffer + ac, n_write - ac);
		if (r == 0)
			return 0;

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				int ret = bcd_io_fd_wait(fd, BCD_IO_FD_WAIT_WR,
				    timeout_abstime);

				if (ret == 1)
					continue;

				errno = EAGAIN;
			}

			return -1;
		}

		ac += r;
		if ((size_t)ac == n_write)
			break;
	}

	return ac;
}

int
bcd_io_fd_prepare(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags == -1)
		return -1;

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;

	return 0;
}

void
bcd_io_fd_close(int fd)
{

	while (close(fd) == -1 && errno == EINTR);
	return;
}

void
bcd_io_event_destroy(bcd_io_event_t *event)
{

	if (event == NULL)
		return;

	free(event);
	return;
}

struct bcd_io_event *
bcd_io_event_create(int fd, bcd_io_event_handler_t *handler, size_t payload,
    bcd_error_t *error)
{
	struct bcd_io_event *event;

	event = malloc(sizeof(*event) + payload);
	if (event == NULL) {
		bcd_error_set(error, 0, "failed to allocate event");
		return NULL;
	}

	event->mask = 0;
	event->handler = handler;
	event->fd = fd;

	return event;
}

void
bcd_io_event_add_to_ready_list(struct bcd_io_event *event)
{

	if (!(event->flags & BCD_IO_EVENT_IN_READY_LIST)) {
		TAILQ_INSERT_TAIL(&readyevents, event, readylink);
		event->flags |= BCD_IO_EVENT_IN_READY_LIST;
	}

	return;
}

void
bcd_io_event_remove_from_ready_list(struct bcd_io_event *event)
{

	if (event->flags & BCD_IO_EVENT_IN_READY_LIST) {
		TAILQ_REMOVE(&readyevents, event, readylink);
		event->flags &= ~BCD_IO_EVENT_IN_READY_LIST;
	}

	return;
}

int
bcd_io_event_ready_list_is_empty(void)
{

	return TAILQ_EMPTY(&readyevents);
}

void
bcd_io_event_dispatch_ready_list(void)
{
	struct bcd_io_event *curr_event, *next_event;

	/*
	 * Iteration is performed safely as the readyevents list may be modified
	 * (removed from) within handlers.
	 */
	curr_event = TAILQ_FIRST(&readyevents);
	while (curr_event != NULL) {
		next_event = TAILQ_NEXT(curr_event, readylink);
		curr_event->handler(curr_event);
		curr_event = next_event;
	}

	return;
}

static int
bcd_io_accept(int fd, struct sockaddr *address, socklen_t *addrlen,
    bcd_error_t *error)
{
	int client = accept(fd, address, addrlen);

	if (client == -1)
		return -1;

	if (bcd_io_fd_prepare(client) == -1) {
		bcd_error_set(error, errno, "failed to prepare client socket");
		return -1;
	}

	return client;
}

static int
bcd_io_socket(int domain, int type, int protocol, bcd_error_t *error)
{
	int fd;

	fd = socket(domain, type, protocol);
	if (bcd_io_fd_prepare(fd) == -1) {
		bcd_error_set(error, errno, "failed to create socket");
		bcd_io_fd_close(fd);
		return -1;
	}

	return fd;
}

static void
bcd_io_listener_accept(bcd_io_event_t *event)
{
	struct bcd_io_listener_state *handler;
	struct sockaddr_un un;
	bcd_error_t error;

	handler = bcd_io_event_payload(event);

	for (;;) {
		bcd_io_event_t *client_event;
		socklen_t addrlen = sizeof(un);
		int client_fd;

		client_fd = bcd_io_accept(event->fd, (struct sockaddr *)&un,
		    &addrlen, &error);
		if (client_fd == -1) {
			if (errno == EAGAIN) {
				bcd_io_event_remove_from_ready_list(event);
				break;
			}

			break;
		}

		client_event = bcd_io_event_create(client_fd, handler->handler,
		    handler->payload, &error);

		if (client_event == NULL) {
			bcd_io_fd_close(client_fd);
			continue;
		}

		handler->accept(client_event, bcd_io_event_mask(event),
		    bcd_io_event_payload(client_event));
	}

	return;
}

int
bcd_io_listener_handler(struct bcd_io_listener *listener,
    bcd_io_listener_handler_t *ac,
    bcd_io_event_handler_t *handler,
    size_t payload,
    bcd_error_t *error)
{
	struct bcd_io_listener_state *state;
	bcd_io_event_t *event;

	event = bcd_io_event_create(listener->fd, bcd_io_listener_accept,
	    sizeof *state, error);
	if (event == NULL)
		return -1;

	state = bcd_io_event_payload(event);
	state->accept = ac;
	state->handler = handler;
	state->payload = payload;

	if (bcd_io_event_add(event, BCD_IO_EVENT_READ, error) == -1) {
		free(event);
		return -1;
	}

	return 0;
}

int
bcd_io_listener_fd(const struct bcd_io_listener *l)
{

	return l->fd;
}

struct bcd_io_listener *
bcd_io_listener_unix(const char *path, int backlog, bcd_error_t *error)
{
	struct bcd_io_listener *listener = malloc(sizeof *listener);
	struct sockaddr_un un;

	if (listener == NULL)
		return NULL;

	if (*path != '/') {
		bcd_error_set(error, 0, "listener requires full path");
		return NULL;
	}

	if (strlen(path) >= sizeof(un.sun_path)) {
		bcd_error_set(error, 0, "UNIX socket path is too long");
		return NULL;
	}

	listener->path = strdup(path);
	if (listener->path == NULL) {
		bcd_error_set(error, 0, "failed to allocate socket path");
		return NULL;
	}

	listener->fd = bcd_io_socket(AF_UNIX, SOCK_STREAM, 0, error);
	if (listener->fd == -1)
		goto error;

	if (unlink(path) == -1 && errno != ENOENT) {
		bcd_error_set(error, errno, "failed to initialize UNIX socket");
		goto error;
	}

	memset(&un, 0, sizeof un);
	strcpy(un.sun_path, path);
	un.sun_family = AF_UNIX;

	if (bind(listener->fd, (struct sockaddr *)&un, sizeof un) == -1) {
		bcd_error_set(error, errno, "failed to bind to socket");
		bcd_io_fd_close(listener->fd);
		goto error;
	}

	if (listen(listener->fd, backlog) == -1) {
		bcd_io_fd_close(listener->fd);
		goto error;
	}

	return listener;

error:
	free((char *)listener->path);
	free(listener);
	return NULL;
}
