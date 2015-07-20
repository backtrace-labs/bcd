#ifndef BCD_INTERNAL_IO_H
#define BCD_INTERNAL_IO_H

#include <sys/queue.h>

#include "bcd.h"

#ifdef __linux__
#include <sys/epoll.h>

#define BCD_IO_EVENT_READ	(EPOLLIN | EPOLLET)
#define BCD_IO_EVENT_WRITE	(EPOLLOUT | EPOLLET)

#ifdef EPOLLRDHUP
#define BCD_IO_EVENT_CLOSE	(EPOLLRDHUP)
#else
#define BCD_IO_EVENT_CLOSE	(EPOLLHUP)
#endif /* !EPOLLRDHUP */

#endif /* __linux__ */

struct bcd_io_event;
typedef void bcd_io_event_handler_t(struct bcd_io_event *);

enum bcd_io_event_flags {
	BCD_IO_EVENT_IN_READY_LIST = 1
};


struct bcd_io_event {
	int fd;
	unsigned int mask;
	bcd_io_event_handler_t *handler;
	enum bcd_io_event_flags flags;
	TAILQ_ENTRY(bcd_io_event) readylink;
	char payload[];
};
typedef struct bcd_io_event bcd_io_event_t;

static inline unsigned int
bcd_io_event_mask(const struct bcd_io_event *event)
{

	return event->mask;
}

static inline void
bcd_io_event_unset(struct bcd_io_event *event, unsigned int mask)
{

	event->mask &= ~mask;
	return;
}

static inline void *
bcd_io_event_payload(struct bcd_io_event *event)
{

	return (void *)event->payload;
}

bcd_io_event_t *bcd_io_event_create(int, bcd_io_event_handler_t *, size_t,
    bcd_error_t *);
void bcd_io_event_destroy(bcd_io_event_t *);
int bcd_io_event_add(bcd_io_event_t *, unsigned int, bcd_error_t *);
int bcd_io_event_remove(bcd_io_event_t *, bcd_error_t *);
int bcd_io_event_has_error(bcd_io_event_t *);

void bcd_io_event_add_to_ready_list(struct bcd_io_event *);
void bcd_io_event_remove_from_ready_list(struct bcd_io_event *);
int bcd_io_event_ready_list_is_empty(void);
void bcd_io_event_dispatch_ready_list(void);

struct bcd_io_listener;
typedef struct bcd_io_listener bcd_io_listener_t;

bcd_io_listener_t *bcd_io_listener_unix(const char *, int, bcd_error_t *);
int bcd_io_listener_fd(const bcd_io_listener_t *);

typedef void bcd_io_listener_handler_t(bcd_io_event_t *,
    unsigned int, void *);

int bcd_io_listener_handler(bcd_io_listener_t *,
    bcd_io_listener_handler_t *,
    bcd_io_event_handler_t *,
    size_t,
    bcd_error_t *);

enum bcd_io_fd_wait {
	BCD_IO_FD_WAIT_RD = 0,
	BCD_IO_FD_WAIT_WR
};

int bcd_io_init(bcd_error_t *);
int bcd_io_enter(bcd_error_t *);
void bcd_io_fd_close(int);
int bcd_io_fd_prepare(int);
ssize_t bcd_io_fd_write(int, const void *, size_t, time_t);
ssize_t bcd_io_fd_read(int, void *, size_t, time_t);
int bcd_io_fd_wait(int, enum bcd_io_fd_wait, time_t);

#endif /* BCD_INTERNAL_IO_H */
