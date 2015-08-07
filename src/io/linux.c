#ifdef __linux__
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#ifndef BCD_IO_NEVENT
#define BCD_IO_NEVENT 128
#endif /* BCD_IO_NEVENT */

static int epoll_fd;

int
bcd_io_event_add(struct bcd_io_event *event, unsigned int mask, bcd_error_t *e)
{
	struct epoll_event ev;

	ev.events = mask;
	ev.data.ptr = event;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event->fd, &ev) == -1) {
		bcd_error_set(e, errno, "failed to watch descriptor");
		return -1;
	}

	bcd_io_event_add_to_ready_list(event);

	return 0;
}

int
bcd_io_event_remove(struct bcd_io_event *event, bcd_error_t *e)
{
	struct epoll_event ev_ignored;

	bcd_io_event_remove_from_ready_list(event);

	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event->fd, &ev_ignored) == -1) {
		bcd_error_set(e, errno,
		    "failed to remove descriptor from watching");
		return -1;
	}

	return 0;
}

int
bcd_io_event_has_error(struct bcd_io_event *event)
{

	return !!(event->mask & EPOLLERR);
}

int
bcd_io_init(struct bcd_error *error)
{

	epoll_fd = epoll_create(BCD_IO_NEVENT);
	if (epoll_fd == -1) {
		error->errnum = errno;
		error->message ="Failed to initialize event loop";
		return -1;
	}

	return 0;
}

int
bcd_io_enter(bcd_error_t *error)
{
	struct epoll_event ev[BCD_IO_NEVENT];

	(void)error;

	for (;;) {
		int n_fd, i, timeout;

		timeout = -1;
		if (!bcd_io_event_ready_list_is_empty())
			timeout = 0;

		n_fd = epoll_wait(epoll_fd, ev, BCD_IO_NEVENT, timeout);
		if (n_fd == -1) {
			if (errno == EINTR)
				continue;

			bcd_error_set(error, errno, "internal event loop "
			    "error");
			return -1;
		}

		for (i = 0; i < n_fd; i++) {
			struct bcd_io_event *event = ev[i].data.ptr;

			event->mask |= ev[i].events;
			bcd_io_event_add_to_ready_list(event);
		}

		bcd_io_event_dispatch_ready_list();
	}

	return 0;
}
#endif /* __linux__ */
