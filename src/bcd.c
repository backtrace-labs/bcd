#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#ifdef __linux__
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#endif /* __linux__ */

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

/* Auto-generated path for socket if unspecified by user. */
#define BCD_US_PATH	"/tmp/bcd.XXXXXX"

#define BCD_MAGIC(N) \
	bcd_MAGICAL_UNICORNS_##N

void (*bcd_pre_trace)(int, siginfo_t *) = NULL;
void (*bcd_post_trace)(int, siginfo_t *) = NULL;

/*
 * Critical communication goes over the pipe, such as total program
 * failure events and early initialization.
 */
struct bcd_pipe {
	int fd[2];
};
typedef struct bcd_pipe bcd_pipe_t;

enum bcd_op {
	/*
	 * Communicates configuration information through pipes, includes
	 * UNIX socket details.
	 */
	BCD_OP_CF = 0,

	/* Server completion of last command. */
	BCD_OP_OK,

	/* Client acknowledges thread-identifier. */
	BCD_OP_TID,

	/* Client set of key-value pair. */
	BCD_OP_KV,

	BCD_OP_TR_PROCESS,
	BCD_OP_TR_THREAD,
	BCD_OP_TR_FATAL,

	/* Client tells monitor to detach. */
	BCD_OP_DETACH,

	/* Client sends argument to ptrace */
	BCD_OP_ARG,
};

struct bcd_packet {
	enum bcd_op op;
	unsigned int length;
	char payload[0];
};

#ifndef BCD_SB_PATH
#define BCD_SB_PATH 1024
#endif /* BCD_SB_PATH */

#ifndef BCD_PACKET_LIMIT
#define BCD_PACKET_LIMIT 1024
#endif /* BCD_PACKET_LIMIT */

struct bcd_kv {
	LIST_ENTRY(bcd_kv) linkage;
	const char *key;
	const char *value;
};
static LIST_HEAD(, bcd_kv) bcd_kv_list = LIST_HEAD_INITIALIZER(&bcd_kv_list);
static size_t bcd_kv_length;
static size_t bcd_kv_count;

struct bcd_arg {
	TAILQ_ENTRY(bcd_arg) linkage;
	const char *arg;
};

static TAILQ_HEAD(, bcd_arg) bcd_arg_list;
static size_t bcd_arg_length;
static size_t bcd_arg_count;

static char *bcd_target_process;

static sig_atomic_t sigalrm_fired;
static sig_atomic_t sigchld_fired;
static sig_atomic_t sigterm_fired;
static const char *unlink_directory;

typedef void bcd_signal_handler_t(int);

static int bcd_sb_read(bcd_pipe_t *, struct bcd_packet *, size_t, time_t,
    bcd_error_t *);
static ssize_t bcd_sb_write(bcd_pipe_t *, enum bcd_op, struct bcd_packet *,
    size_t, time_t);

#ifndef BCD_ARGC_LIMIT
#define BCD_ARGC_LIMIT 32
#endif /* BCD_ARGC_LIMIT */

#ifndef BCD_ARGV_LIMIT
#define BCD_ARGV_LIMIT 1024
#endif /* BCD_ARGV_LIMIT */

#ifndef BCD_KV_LIMIT
#define BCD_KV_LIMIT 1024
#endif /* BCD_KV_LIMIT */

struct bcd_sb {
	pid_t master_pid;
	pid_t monitor_pid;
	bcd_pipe_t master;
	bcd_pipe_t monitor;
	char path[BCD_SB_PATH];
	int output_fd;
};

static union {
	struct bcd_sb sb;
	char storage[BCD_MD_PAGESIZE];
} pcb BCD_CC_ALIGN(BCD_MD_PAGESIZE) BCD_CC_SECTION("BACKTRACE_IO_BCD");

#define BCD_PACKET_INSTANCE(L)			\
	struct {				\
		struct bcd_packet packet;	\
		char payload[L];		\
	}

#define BCD_PACKET(P)	      (&(P)->packet)
#define BCD_PACKET_PAYLOAD(P) ((void *)((P)->payload))

/*
 * BCD_PACKET_SIZE should only be called when BCD_PACKET_INSTANCE is invoked
 * with a non-zero argument. It should be used for static lengths in the same
 * context one would use sizeof (*ptr) (instead of baking the type into the
 * code).
 */
#define BCD_PACKET_SIZE(P)    (sizeof ((P)->payload))

enum bcd_session_state {
	BCD_SESSION_READING,
	BCD_SESSION_WRITING
};

struct bcd_session {
	pid_t tid;
	enum bcd_session_state state;
	int terminated;
	size_t offset;
	BCD_PACKET_INSTANCE(BCD_PACKET_LIMIT) packet;
};

static void bcd_handler_request_response(bcd_io_event_t *client);
static int bcd_read_request(int fd, struct bcd_session *);
static int bcd_perform_request(struct bcd_session *session);
static int bcd_write_ack(int fd, struct bcd_session *);

static void
bcd_default_signal_handler(int s, siginfo_t *si, void *unused)
{

	(void)unused;
	(void)si;
	(void)s;

	if (bcd_pre_trace != NULL)
		bcd_pre_trace(s, si);

	bcd_fatal("Fatal signal received.");

	if (bcd_post_trace != NULL)
		bcd_post_trace(s, si);

	_exit(EXIT_FAILURE);
}

static void
bcd_default_signal_handler_raise(int s, siginfo_t *si, void *unused)
{

	(void)unused;
	(void)si;

	if (bcd_pre_trace != NULL)
		bcd_pre_trace(s, si);

	bcd_fatal("Fatal signal received.");

	if (bcd_post_trace != NULL)
		bcd_post_trace(s, si);

	signal(s, SIG_DFL);
	return;
}

int
bcd_sigaction_internal(void (*h)(int, siginfo_t *, void *),
    unsigned int flags, int (*sah)(int, const struct sigaction *,
    struct sigaction *))
{
	int signals[] = {
		SIGSEGV,
		SIGFPE,
		SIGABRT,
		SIGBUS,
		SIGILL,
		SIGFPE
	};
	struct sigaction sa;
	size_t i;

	if (sah == NULL)
		sah = sigaction;

	if (h != NULL) {
		sa.sa_sigaction = h;
	} else if (flags & BCD_SIGACTION_RAISE) {
		sa.sa_sigaction = bcd_default_signal_handler_raise;
	} else {
		sa.sa_sigaction = bcd_default_signal_handler;
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

	for (i = 0; i < sizeof(signals) / sizeof(*signals); i++) {
		if (sah(signals[i], &sa, NULL) == -1)
			return signals[i];
	}

	return 0;
}

int
bcd_sigaction(void (*h)(int, siginfo_t *, void *), unsigned int flags)
{

	return bcd_sigaction_internal(h, flags, NULL);
}

static void
handle_sigalrm(int sig)
{

	(void)sig;
	sigalrm_fired = 1;
	return;
}


static void
handle_sigchld(int sig)
{

	(void)sig;
	sigchld_fired = 1;
	return;
}

static void
handle_sigterm(int sig)
{

	(void)sig;
	sigterm_fired = 1;
	return;
}

static int
bcd_error(enum bcd_event event, const struct bcd_session *session,
    const char *string, int code)
{
	pid_t tid = 0;

	if (session != NULL)
		tid = session->tid;

	bcd_config.handler(event, pcb.sb.master_pid, tid, string, code);
	return -1;
}

const char *
bcd_error_message(const struct bcd_error *const e)
{

	return e->message;
}

int
bcd_error_errno(const struct bcd_error *const e)
{

	return e->errnum;
}

static void
bcd_child_exit(int e)
{
	/* On Linux we use '@' to specify an abstract socket.
	 * They aren't on the filesystem so they can't be unlinked.
	 */
#ifdef __linux__
	if (bcd_config.ipc.us.path[0] != '@')
#endif
		unlink(bcd_config.ipc.us.path);

	if (unlink_directory != NULL)
		rmdir(unlink_directory);

	_exit(e);
}

#ifdef __linux__
#if !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 30)
static pid_t
gettid(void)
{

	return syscall(__NR_gettid);
}
#endif /* !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 30) */
#endif /* __linux__ */

#ifdef __linux__
#if !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 38)
static size_t
strlcpy(char *dst, const char *src, size_t n)
{
	size_t len = strlen(src);

	if (n > 0) {
		size_t copy = len < n ? len : (n - 1);
		memmove(dst, src, copy);
		dst[copy] = '\0';
	}

	return len;
}
#endif /* !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 38) */
#endif /* __linux__ */

void
bcd_error_handler_default(enum bcd_event event, pid_t pid, pid_t tid,
    const char *message, int code)
{

	fprintf(stderr, "[%d] process(%ju)/thread(%ju): %s: %d\n",
	    event, (uintmax_t)pid, (uintmax_t)tid, message, code);
	return;
}

void
bcd_error_set(struct bcd_error *e, int err, const char *m)
{

	e->errnum = err;
	e->message = m;
	return;
}

static void
bcd_pipe_ensure_readonly(struct bcd_pipe *p)
{

	while (close(p->fd[1]) == -1 && errno == EINTR);
	p->fd[1] = -1;
	return;
}

static void
bcd_pipe_ensure_writeonly(struct bcd_pipe *p)
{

	while (close(p->fd[0]) == -1 && errno == EINTR);
	p->fd[0] = -1;
	return;
}

static int
bcd_pipe_init(struct bcd_pipe *p, struct bcd_error *error)
{

	if (pipe(p->fd) == -1) {
		bcd_error_set(error, errno, "could not create create pipe");
		return -1;
	}

	if (bcd_io_fd_prepare(p->fd[0]) == -1 ||
	    bcd_io_fd_prepare(p->fd[1]) == -1) {
		bcd_error_set(error, errno,
		    "internal descriptor management error");
		goto fail;
	}

	return 0;

fail:
	bcd_io_fd_close(p->fd[0]);
	bcd_io_fd_close(p->fd[1]);
	return -1;
}

static void
bcd_pipe_deinit(struct bcd_pipe *p)
{

	bcd_io_fd_close(p->fd[0]);
	bcd_io_fd_close(p->fd[1]);
	return;
}

static ssize_t
bcd_packet_write(int fd, struct bcd_packet *packet, size_t length,
    time_t timeout_abstime)
{

	packet->length = length;
	return bcd_io_fd_write(fd, packet, sizeof(*packet) + length,
	    timeout_abstime);
}

static void
bcd_handler_accept(bcd_io_event_t *client, unsigned int mask, void *closure)
{
	struct bcd_session *session = closure;
	bcd_error_t error;

	(void)mask;

	memset(session, 0, sizeof *session);
	if (bcd_io_event_add(client,
	    BCD_IO_EVENT_READ | BCD_IO_EVENT_WRITE | BCD_IO_EVENT_CLOSE,
	    &error) == -1) {
		bcd_io_event_destroy(client);
	}

	return;
}

static int
bcd_write_ack(int fd, struct bcd_session *session)
{
	struct bcd_packet *packet = BCD_PACKET(&session->packet);
	size_t ac = session->offset;

	packet->op = BCD_OP_OK;
	packet->length = 0;

	do {
		ssize_t r = write(fd, (char *)packet + ac,
		    sizeof(*packet) - ac);

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				session->offset = ac;
				return -1;
			}

			bcd_error(BCD_EVENT_FATAL, session,
			    "unknown communication error", errno);
			bcd_child_exit(EXIT_FAILURE);
		}

		if (r == 0) {
			bcd_error(BCD_EVENT_FATAL, session,
			    "premature process termination", r);
			bcd_child_exit(EXIT_FAILURE);
		}

		ac += (size_t)r;
	} while (ac < sizeof *packet);

	session->offset = 0;

	return 0;
}

static int
bcd_channel_read_ack(int fd, time_t timeout_abstime, bcd_error_t *error)
{
	BCD_PACKET_INSTANCE(0) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	ssize_t r;
	ssize_t ac = 0;

	packet->op = BCD_OP_OK;
	packet->length = 0;

	r = bcd_io_fd_read(fd, (char *)packet + ac, sizeof(*packet),
	    timeout_abstime);
	if (r < 0) {
		if (errno == EAGAIN) {
			bcd_error_set(error, errno, "timed out");
		} else {
			bcd_error_set(error, errno, "failed to acknowledge");
		}
		return -1;
	} else if (r == 0) {
		bcd_error_set(error, 0, "premature termination");
		return -1;
	} else if ((size_t)r < sizeof(*packet)) {
		bcd_error_set(error, 0, "truncated response");
		return -1;
	}

	assert(r == sizeof(*packet));

	if (packet->op != BCD_OP_OK) {
		bcd_error_set(error, 0, "dispatch failed");
		return -1;
	}

	return 0;
}

void
bcd_reap(void)
{
	unsigned int timeout = 0;
	int wstatus, r;

	do {
		r = waitpid(pcb.sb.monitor_pid, &wstatus, WNOHANG);
		if (r == -1)
			break;

		if (r == 0)
			continue;

		if (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus))
			continue;
	} while (sleep(1), timeout++ < bcd_config.timeout);

	return;
}

/*
 * Requests trace and signals child that it should exit.
 */
void
bcd_fatal(volatile const char *message)
{
	BCD_PACKET_INSTANCE(0) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	bcd_pipe_t *pd = &pcb.sb.master;
	volatile const char *BCD_MAGIC(message);
	bcd_error_t error;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	BCD_MAGIC(message) = message;
	BCD_CC_FORCE(BCD_MAGIC(message), message);

	bcd_sb_write(pd, BCD_OP_TR_FATAL, packet, 0, timeout_abstime);

	/* Wait for child to exit. */
	bcd_sb_read(&pcb.sb.monitor, packet, 0, timeout_abstime, &error);
	bcd_reap();
	return;
}

/*
 * Construct key-value string according to latest key-value list.
 *   - output: Array of pointers to strings.
 *   - n_output: Length of array.
 *   - s: Seperator, if specified, then only the first element of output
 *     is set. Otherwise, prefix is duplicated.
 *   - ks: Key-value seperator.
 *   - prefix: The prefix for the option. For example, "--kv=" or "-k".
 */
static ssize_t
bcd_kv_get(char **output, size_t n_output,
    const char s, const char ks, const char *prefix, bcd_error_t *error)
{
	struct bcd_kv *cursor;
	size_t limit = n_output;
	size_t i = 0;

	if (bcd_kv_count == 0 ||
	    bcd_config.invoke.kp == NULL) {
		return 0;
	}

	if (n_output > bcd_kv_count)
		limit = bcd_kv_count;

	if (limit > BCD_ARGC_LIMIT)
		limit = BCD_ARGC_LIMIT;

	if (s == 0) {
		LIST_FOREACH(cursor, &bcd_kv_list, linkage) {
			int ra;

			if (i == limit)
				break;

			ra = asprintf(&output[i++], "%s%s%c%s",
			    prefix, cursor->key, ks, cursor->value);
			if (ra == -1) {
				bcd_error_set(error, 0, "failed to allocate "
				    "key-value pair");
				goto fail;
			}
		}
	} else {
		size_t p_l = strlen(prefix);

		i++;

		output[0] = malloc(p_l + bcd_kv_count +
		    bcd_kv_length + 1);
		if (output[0] == NULL) {
			bcd_error_set(error, 0, "failed to allocate single "
			    "key-value pair list");
			goto fail;
		}

		memcpy(output[0], prefix, p_l);
		LIST_FOREACH(cursor, &bcd_kv_list, linkage) {
			size_t delta = strlen(cursor->key);

			memcpy(output[0] + p_l, cursor->key, delta);
			p_l += delta;
			output[0][p_l++] = ks;

			delta = strlen(cursor->value);
			memcpy(output[0] + p_l, cursor->value, delta);
			p_l += delta;

			if (LIST_NEXT(cursor, linkage) != NULL)
				output[0][p_l++] = s;
		}
		output[0][p_l] = '\0';
	}

	return (ssize_t)i;

fail:
	while (i-- > 0)
		free(output[i]);

	return -1;
}

static int
bcd_kv_set(struct bcd_session *session, struct bcd_packet *packet)
{
	struct bcd_kv *kv, *previous;
	const char *key = packet->payload;
	const char *value;
	char *stream, *e;
	size_t k_l, v_l;

	if (*key == '\0')
		goto fail;

	value = memchr(key, '\0', packet->length);
	if (value == NULL)
		goto fail;
	k_l = value - key;

	value++;
	e = memchr(value, '\0', packet->length - k_l - 1);
	if (e == NULL)
		goto fail;
	v_l = e - value;

	if (value >= packet->payload + packet->length)
		goto fail;

	kv = malloc(sizeof(*kv) + k_l + v_l + 2);
	if (kv == NULL) {
		return bcd_error(BCD_EVENT_METADATA, session,
		    "internal memory allocation error", errno);
	}

	if (bcd_kv_count == 0)
		LIST_INIT(&bcd_kv_list);

	LIST_FOREACH(previous, &bcd_kv_list, linkage) {
		if (strcmp(previous->key, key) == 0) {
			bcd_kv_length -= strlen(previous->key) +
			    strlen(previous->value) + 1;
			LIST_REMOVE(previous, linkage);
			free(previous);
			bcd_kv_count--;
			break;
		}
	}

	stream = (char *)&kv[1];
	memcpy(stream, key, k_l + 1);
	kv->key = stream;

	memcpy(stream + k_l + 1, value, v_l + 1);
	kv->value = stream + k_l + 1;

	LIST_INSERT_HEAD(&bcd_kv_list, kv, linkage);
	bcd_kv_count++;
	bcd_kv_length += k_l + v_l + 1;
	return 0;
fail:
	return bcd_error(BCD_EVENT_METADATA, session,
	    "malformed key-value pair", 0);
}

static ssize_t
bcd_arg_get(char **output, size_t n_output, bcd_error_t *error)
{
	struct bcd_arg *cursor;
	size_t limit = n_output;
	size_t i = 0;

	if (bcd_arg_count == 0) {
		return 0;
	}

	if (n_output > bcd_arg_count)
		limit = bcd_arg_count;

	if (limit > BCD_ARGC_LIMIT)
		limit = BCD_ARGC_LIMIT;

	TAILQ_FOREACH(cursor, &bcd_arg_list, linkage) {
		int ra;

		if (i == limit)
			break;

		ra = asprintf(&output[i++], "%s", cursor->arg);
		if (ra == -1) {
			bcd_error_set(error, 0, "failed to allocate arg");
			goto fail;
		}
	}

	return (ssize_t)i;
fail:
	while (i-- > 0)
		free(output[i]);

	return -1;
}

static int
bcd_arg_set(struct bcd_session *session, struct bcd_packet *packet)
{
	const char *arg = packet->payload;
	struct bcd_arg *argp, *cursor;
	size_t arglen;
	char *stream;

	arglen = strlen(arg);
	if (arglen == 0)
		goto fail;

	argp = malloc(sizeof(*argp) + arglen + 1);
	if (argp == NULL) {
		return bcd_error(BCD_EVENT_METADATA, session,
		    "internal memory allocation error", errno);
	}

	if (bcd_arg_count == 0) {
		TAILQ_INIT(&bcd_arg_list);
	} else {
		TAILQ_FOREACH(cursor, &bcd_arg_list, linkage) {
			if (strcmp(cursor->arg, arg) == 0) {
				bcd_arg_length -= strlen(cursor->arg) + 1;
				TAILQ_REMOVE(&bcd_arg_list, cursor, linkage);
				free(cursor);
				bcd_arg_count--;
				break;
			}
		}
	}

	stream = (char *)&argp[1];
	memcpy(stream, arg, arglen + 1);
	argp->arg = stream;

	TAILQ_INSERT_TAIL(&bcd_arg_list, argp, linkage);
	bcd_arg_count++;
	bcd_arg_length += arglen + 1;
	return 0;
fail:
	return bcd_error(BCD_EVENT_METADATA, session,
	    "malformed argument", 0);
}

int
bcd_backtrace(const struct bcd *const bcd,
    enum bcd_target target, bcd_error_t *error)
{
	struct bcd_packet packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	packet.op = BCD_OP_TR_PROCESS;
	if (target == BCD_TARGET_THREAD)
		packet.op = BCD_OP_TR_THREAD;

	packet.length = 0;
	r = bcd_packet_write(bcd->fd, &packet, 0, timeout_abstime);
	if (r < 0) {
		bcd_error_set(error, errno, "failed to invoke tracer");
		return -1;
	}

	return bcd_channel_read_ack(bcd->fd, timeout_abstime, error);
}

void
bcd_emit(const struct bcd *const bcd, volatile const char *message)
{
	volatile const char *BCD_MAGIC(message);
	bcd_error_t error;

	BCD_MAGIC(message) = message;
	BCD_CC_FORCE(BCD_MAGIC(message), message);

	bcd_backtrace(bcd, BCD_TARGET_THREAD, &error);
	return;
}

void
bcd_abort(void)
{

	bcd_error(BCD_EVENT_FATAL, NULL, "unrecoverable internal error", 0);
	return;
}

static pid_t
vfork_tracer(char **argv)
{
	pid_t tracer_pid;

	tracer_pid = vfork();
	if (tracer_pid == 0) {
		char* const empty_env[] = {NULL};
		char* const * envp = empty_env;
		if (bcd_config.flags & BCD_CONFIG_F_TRACERINHERITENV)
			envp = environ;
		if (execve(bcd_config.invoke.path, argv, envp) == -1)
			_exit(EXIT_FAILURE);
	}

	return tracer_pid;
}

static int
signal_check(int *sig)
{
	int r = 1;

	if (sigterm_fired) {
		*sig = SIGTERM;
		sigterm_fired = 0;
	} else if (sigchld_fired) {
		*sig = SIGCHLD;
		sigchld_fired = 0;
	} else if (sigalrm_fired) {
		*sig = SIGALRM;
		sigalrm_fired = 0;
	} else {
		r = 0;
	}

	return r;
}

/*
 * bcd_execve is guaranteed to never mutate arguments argv[N]
 * where N < fr.
 */
static int
bcd_execve(struct bcd_session *session, char **argv, size_t fr)
{
	const struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
	sigset_t blockset, interestset, origset;
	bcd_signal_handler_t *old_sigalrm_handler,
	    *old_sigchld_handler, *old_sigterm_handler;
	pid_t tracer_pid;
	int retval = 0;
	int sig, tracer_status;
	int wait_ret = 0;

	sigfillset(&blockset);
	sigemptyset(&interestset);
	sigaddset(&interestset, SIGALRM);
	sigaddset(&interestset, SIGCHLD);
	sigaddset(&interestset, SIGTERM);
	sigprocmask(0, NULL, &origset);

	sigalrm_fired = 0;
	old_sigalrm_handler = signal(SIGALRM, handle_sigalrm);
	sigchld_fired = 0;
	old_sigchld_handler = signal(SIGCHLD, handle_sigchld);
	sigterm_fired = 0;
	old_sigterm_handler = signal(SIGTERM, handle_sigterm);

	if (bcd_config.timeout != 0)
		alarm(bcd_config.timeout);

	tracer_pid = vfork_tracer(argv);
	if (tracer_pid == -1) {
		retval = bcd_error(BCD_EVENT_TRACE, session,
		    "failed to execute tracer", errno);
		goto leave;
	}

	sigprocmask(SIG_SETMASK, &blockset, NULL);

	for (;;) {
		/*
		 * Handle the cases where SIGALRM, SIGCHLD, or SIGTERM fired
		 * after vfork() and before sigprocmask().
		 */
		if (signal_check(&sig) == 0) {
			sig = sigtimedwait(&interestset, NULL, &timeout);
			if (sig <= 0) {
				int e = errno;
				if (signal_check(&sig) == 0
				  && (e == EINTR || e == EAGAIN)) {
				  continue;
				}
			}
		}

		switch (sig) {
		case SIGALRM:
			kill(tracer_pid, SIGKILL);
			retval = bcd_error(BCD_EVENT_TRACE, session,
			    "tracer time out", 0);
			goto leave;
		case SIGCHLD:
			wait_ret = waitpid(tracer_pid, (int *)&tracer_status,
			    WNOHANG);
			if (wait_ret == -1) {
				retval = bcd_error(BCD_EVENT_TRACE,
				    session, "failed to wait for tracer", errno);
				goto leave;
			}

			if (!WIFEXITED(tracer_status) &&
			    !WIFSIGNALED(tracer_status))
				continue;
			if (WIFEXITED(tracer_status)) {
				if (WEXITSTATUS(tracer_status) != 0) {
					retval = bcd_error(BCD_EVENT_TRACE,
					    session, "tracer exited non-zero", 0);
					goto leave;
				}
			}
			if (WIFSIGNALED(tracer_status)) {
				retval = bcd_error(BCD_EVENT_TRACE, session,
				    "tracer killed with signal", 0);
				goto leave;
			}
			/* The tracer exited successfully. */
			assert(WIFEXITED(tracer_status));
			assert(WEXITSTATUS(tracer_status) == 0);
			assert(retval == 0);
			goto leave;
		case SIGTERM:
			kill(tracer_pid, SIGTERM);
			_exit(128 + SIGTERM); /* Per POSIX */
		default:
			/* UNREACHABLE */
			abort();
		}
	}

leave:
	signal(SIGALRM, old_sigalrm_handler);
	signal(SIGCHLD, old_sigchld_handler);
	signal(SIGTERM, old_sigterm_handler);
	sigprocmask(SIG_SETMASK, &origset, NULL);

	while (argv[fr] != NULL)
		free(argv[fr++]);

	return retval;
}

static int
bcd_request_handler(pid_t tid, struct bcd_session *session)
{

	if (tid == 0 && session != NULL)
		tid = session->tid;

	if (bcd_config.request_handler != NULL &&
	    bcd_config.request_handler(tid) == -1) {
		return bcd_error(BCD_EVENT_TRACE, session,
		    "request handler intercepted event", 0);
	}

	return 0;
}

static int
bcd_backtrace_thread(struct bcd_session *session)
{
	union {
		char *argv[BCD_ARGC_LIMIT];
		const char *cargv[BCD_ARGC_LIMIT];
	} u;
	bcd_error_t error;
	char *tp = NULL;;
	pid_t tid = session->tid;
	ssize_t r;
	size_t delta = 0;

	if (bcd_request_handler(tid, session) == -1)
		return -1;

	u.cargv[delta++] = bcd_config.invoke.path;

	r = bcd_arg_get(&(u.argv[delta]), sizeof(u.argv) / sizeof(*u.argv) - 2,
	    &error);
	if (r == -1) {
		free(tp);
		return bcd_error(BCD_EVENT_TRACE, session,
		    error.message, 0);
	}
	delta += r;

	u.cargv[delta++] = bcd_target_process;

	if (bcd_config.invoke.tp != NULL) {
		if (asprintf(&tp, "%s%ju", bcd_config.invoke.tp,
		    (uintmax_t)tid) == -1) {
			return bcd_error(BCD_EVENT_TRACE, session,
			    "failed to construct tracer string", 0);
		}

		u.argv[delta++] = tp;
	}

	r = bcd_kv_get(&(u.argv[delta]),
	    sizeof(u.argv) / sizeof(*u.argv) - (delta + 1),
	    bcd_config.invoke.separator,
	    bcd_config.invoke.ks,
	    bcd_config.invoke.kp, &error);
	if (r == -1) {
		free(tp);
		return bcd_error(BCD_EVENT_TRACE, session,
		    error.message, 0);
	}

	u.argv[r + delta] = NULL;
	return bcd_execve(session, u.argv, delta - (tp != NULL));
}

static int
bcd_backtrace_process(struct bcd_session *session)
{
	union {
		char *argv[BCD_ARGC_LIMIT];
		const char *cargv[BCD_ARGC_LIMIT];
	} u;
	bcd_error_t error;
	size_t delta = 0;
	ssize_t r;

	if (bcd_request_handler(0, session) == -1)
		return -1;

	u.cargv[delta++] = strdup(bcd_config.invoke.path);

	r = bcd_arg_get(&(u.argv[delta]), sizeof(u.argv) / sizeof(*u.argv) - 2,
	    &error);
	if (r == -1) {
		return bcd_error(BCD_EVENT_TRACE, session,
		    error.message, 0);
	}
	delta += r;

	u.cargv[delta++] = bcd_target_process;

	r = bcd_kv_get(&(u.argv[delta]),
	    sizeof(u.argv) / sizeof(*u.argv) - (delta + 1),
	    bcd_config.invoke.separator,
	    bcd_config.invoke.ks,
	    bcd_config.invoke.kp, &error);
	if (r == -1)
		return bcd_error(BCD_EVENT_TRACE, session, error.message, 0);

	u.argv[r + delta] = NULL;
	return bcd_execve(session, u.argv, delta);
}

static int
bcd_perform_request(struct bcd_session *session)
{
	struct bcd_packet *packet = BCD_PACKET(&session->packet);

	switch (packet->op) {
	case BCD_OP_TID:
		memcpy(&session->tid, packet->payload, sizeof session->tid);
		break;
	case BCD_OP_KV:
		return bcd_kv_set(session, packet);
	case BCD_OP_ARG:
		return bcd_arg_set(session, packet);
	case BCD_OP_TR_THREAD:
		return bcd_backtrace_thread(session);
	case BCD_OP_TR_PROCESS:
		return bcd_backtrace_process(session);
	case BCD_OP_TR_FATAL:
		bcd_backtrace_process(session);
		bcd_child_exit(EXIT_SUCCESS);
		break;
	case BCD_OP_DETACH:
		session->terminated = 1;
		break;
	default:
		break;
	}

	return 0;
}

static void
bcd_handler_request_response(bcd_io_event_t *client)
{
	bcd_error_t error;
	struct bcd_session *session = bcd_io_event_payload(client);

	int ret;

	switch (session->state) {
	case BCD_SESSION_READING:
		ret = bcd_read_request(client->fd, session);
		if (ret == -1) {
			if (errno == EAGAIN) {
				bcd_io_event_unset(client, BCD_IO_EVENT_READ);
				bcd_io_event_remove_from_ready_list(client);
				return;
			}
		}
		if (session->terminated)
			break;
		bcd_perform_request(session);
		/* FALLTHROUGH */
	case BCD_SESSION_WRITING:
		ret = bcd_write_ack(client->fd, session);
		if (ret == -1) {
			if (errno == EAGAIN) {
				bcd_io_event_unset(client, BCD_IO_EVENT_WRITE);
				bcd_io_event_remove_from_ready_list(client);
				return;
			}
		}
		break;
	default:
		/* UNREACHABLE */
		assert(session->state == BCD_SESSION_READING ||
		    session->state == BCD_SESSION_WRITING);
		abort();
	}

	if (session->terminated) {
		bcd_io_fd_close(client->fd);
		bcd_io_event_remove_from_ready_list(client);
		bcd_io_event_remove(client, &error);
		bcd_io_event_destroy(client);
	}

	return;
}

static int
bcd_read_request(int fd, struct bcd_session *session)
{
	struct bcd_packet *packet = BCD_PACKET(&session->packet);
	size_t ac = session->offset;
	size_t target = 0;

	if (ac > sizeof *packet)
		target = packet->length;

	do {
		ssize_t r = read(fd, (char *)packet + ac,
		    sizeof(*packet) + target - ac);

		if (r == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN) {
				session->offset = ac;
				return -1;
			}

			bcd_error(BCD_EVENT_FATAL, session,
			    "unexpected termination of stream", errno);
			goto fail;
		}

		if (r == 0) {
			if (session->terminated) {
				/*
				 * It is expected that we may read until EOF
				 * after termination.
				 */
				return 0;
			}

			bcd_error(BCD_EVENT_FATAL, session,
			    "unexpected termination of stream", 0);
			goto fail;
		}

		ac += (size_t)r;
		if (ac >= sizeof *packet) {
			target = packet->length;
			if (target > BCD_PACKET_LIMIT) {
				bcd_error(BCD_EVENT_FATAL, session,
				    "message size is too large", (int)target);
				bcd_child_exit(EXIT_FAILURE);
			}
		}
	} while (ac < sizeof *packet + target);

	session->offset = 0;
	return 0;

fail:
	bcd_child_exit(EXIT_FAILURE);
	return -1; /* Unreachable */
}

static ssize_t
bcd_sb_write(bcd_pipe_t *pd, enum bcd_op op, struct bcd_packet *packet,
    size_t length, time_t timeout_abstime)
{

	packet->op = op;
	packet->length = length;

	return bcd_io_fd_write(pd->fd[1], packet,
	    sizeof(*packet) + length, timeout_abstime);
}

static int
bcd_sb_read(bcd_pipe_t *pd, struct bcd_packet *packet, size_t length,
    time_t timeout_abstime, bcd_error_t *error)
{
	ssize_t r;
	int header_complete = 0;

	/* Read packet header. */
	r = bcd_io_fd_read(pd->fd[0], (char *)packet, sizeof(*packet),
	    timeout_abstime);
	if ((size_t) r != sizeof(*packet))
		goto fail;
	if (packet->length > length)
		goto fail;
	header_complete = 1;

	/* Read packet payload. */
	r += bcd_io_fd_read(pd->fd[0], (char *)&packet[1], packet->length,
	    timeout_abstime);
fail:
	if (r < 0) {
		if (errno == EAGAIN) {
			bcd_error_set(error, errno, "timed out");
		} else {
			bcd_error_set(error, errno, "failed to read response");
		}
		return -1;
	} else if (r == 0) {
		bcd_error_set(error, 0, "premature termination");
		return -1;
	} else if ((size_t)r < sizeof(*packet) +
	    (header_complete ? packet->length : 0)) {
		bcd_error_set(error, 0, "truncated response");
		return -1;
	}

	assert((size_t)r == sizeof(*packet) +
	    (header_complete ? packet->length : 0));
	return 0;
}

int
bcd_kv(struct bcd *bcd, const char *key, const char *value, bcd_error_t *e)
{
	BCD_PACKET_INSTANCE(BCD_PACKET_LIMIT) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	char *payload = packet->payload;
	int fd = bcd->fd;
	size_t k_l = strlen(key) + 1;
	size_t v_l = strlen(value) + 1;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	if (k_l + v_l > BCD_PACKET_LIMIT) {
		bcd_error_set(e, 0, "key-value pair is too long");
		return -1;
	}

	packet->op = BCD_OP_KV;
	memcpy(payload, key, k_l);
	memcpy(payload + k_l, value, v_l);
	packet->length = k_l + v_l;

	r = bcd_packet_write(fd, packet, packet->length, timeout_abstime);
	if (r == -1) {
		bcd_error_set(e, errno, "failed to write kv-pair");
		bcd_io_fd_close(fd);
		return -1;
	}

	return bcd_channel_read_ack(fd, timeout_abstime, e);
}

int
bcd_arg(struct bcd *bcd, const char *arg, bcd_error_t *e)
{
	BCD_PACKET_INSTANCE(BCD_PACKET_LIMIT) st;
	struct bcd_packet *packet = BCD_PACKET(&st);
	char *payload = packet->payload;
	int fd = bcd->fd;
	size_t arglen = strlen(arg) + 1;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	if (arglen > BCD_PACKET_LIMIT) {
		bcd_error_set(e, 0, "argument is too long");
		return -1;
	}

	packet->op = BCD_OP_ARG;
	memcpy(payload, arg, arglen);
	packet->length = arglen;

	r = bcd_packet_write(fd, packet, packet->length, timeout_abstime);
	if (r == -1) {
		bcd_error_set(e, errno, "failed to write argument");
		bcd_io_fd_close(fd);
		return -1;
	}

	return bcd_channel_read_ack(fd, timeout_abstime, e);
}

static void
bcd_handler_fatal(bcd_io_event_t *client)
{
	ssize_t r;
	char c;

	/*
	 * Handle the case where we start off in ready list. It is expected
	 * that the read should fail with EAGAIN.
	 */
	r = read(client->fd, &c, sizeof(c));
	if (r == -1 && errno == EAGAIN) {
		bcd_io_event_remove_from_ready_list(client);
		return;
	}

	/*
	 * We may arrive here because our parent exited and bcd_handler_sb didn't run
	 * yet. Only take a backtrace if our parent actually wrote a request to do
	 * so.
	 */
	if (r > 0) {
		bcd_backtrace_process(NULL);
	}

	bcd_child_exit(EXIT_SUCCESS);
}

/*
 * Kill child in the event of any close operation.
 */
static void
bcd_handler_sb(bcd_io_event_t *client)
{
	/*
	 * Handle the case where we start off in ready list. It is expected
	 * that we will not be in an error condition unless the client
	 * thread has disconnected.
	 */
	if (!bcd_io_event_has_error(client)) {
		bcd_io_event_remove_from_ready_list(client);
		return;
	}

	bcd_child_exit(EXIT_FAILURE);
}

static int
bcd_uid_name(uid_t *uid, const char *name, bcd_error_t *error)
{
	struct passwd pw, *pwd;
	long n_buffer;
	char *buffer;
	int r;

	n_buffer = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (n_buffer == -1)
		n_buffer = 16384;

	buffer = malloc(n_buffer);
	if (buffer == NULL) {
		bcd_error_set(error, errno, "failed to allocate "
		    "internal buffer");
		return -1;
	}

	r = getpwnam_r(name,
	    &pw, buffer, n_buffer, &pwd);

	if (pwd == NULL) {
		int errnum = 0;

		if (r != 0)
			errnum = errno;

		bcd_error_set(error, errnum,
		    "failed to find user for chown");
		free(buffer);
		return -1;
	}

	*uid = pwd->pw_uid;
	free(buffer);

	return 0;
}

static int
bcd_gid_name(gid_t *gid, const char *name, bcd_error_t *error)
{
	struct group gr, *grp;
	long n_buffer;
	char *buffer;
	int r;

	n_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (n_buffer == -1)
		n_buffer = 16384;

	buffer = malloc(n_buffer);
	if (buffer == NULL) {
		bcd_error_set(error, errno, "failed to allocate "
		    "internal buffer");
		return -1;
	}

	r = getgrnam_r(name, &gr,
	    buffer, n_buffer, &grp);
	if (grp == NULL) {
		int errnum = 0;

		if (r != 0)
			errnum = errno;

		bcd_error_set(error, errnum,
		    "failed to find group");
		free(buffer);
		return -1;
	}

	*gid = grp->gr_gid;
	free(buffer);

	return 0;
}

static int
bcd_chown(const char *path, bcd_error_t *error)
{
	const char *gr;
	uid_t uid = 0;
	gid_t gid = 0;

	if (bcd_config.chown.user == NULL)
		return 0;

	if (bcd_uid_name(&uid, bcd_config.chown.user, error) == -1)
		return -1;

	gr = bcd_config.chown.group;
	if (gr == NULL) {
		gid = -1;
	} else if (bcd_gid_name(&gid, gr, error) == -1) {
		return -1;
	}

	if (chown(path, uid, gid) == -1) {
		bcd_error_set(error, errno, "failed to set permissions");
		return -1;
	}

	return 0;
}

static int
bcd_suid(bcd_error_t *error)
{
	uid_t uid = 0;
	gid_t gid = 0;

	if (bcd_config.chown.group != NULL) {
		if (bcd_gid_name(&gid, bcd_config.chown.group, error) == -1)
			return -1;

		if (getegid() != gid && setgid(gid) == -1) {
			bcd_error_set(error, errno,
			    "failed to drop group privileges");
			return -1;
		}
	}

	if (bcd_config.chown.user == NULL)
		return 0;

	if (bcd_uid_name(&uid, bcd_config.suid.user, error) == -1)
		return -1;

	if (geteuid() != uid && setuid(uid) == -1) {
		bcd_error_set(error, errno, "failed to drop user privileges");
		return -1;
	}

	return 0;
}

static void
bcd_child(void)
{
	BCD_PACKET_INSTANCE(BCD_SB_PATH) packet;
	sigset_t emptyset;
	bcd_error_t error;
	bcd_io_listener_t *listener;
	bcd_io_event_t *event;
	ssize_t r;

	if (bcd_config.monitor_init != NULL)
		bcd_config.monitor_init();

	bcd_set_cpu_affinity(bcd_config.affinity.target_cpu);

	if (pcb.sb.output_fd != -1) {
		int ret;

		do {
			ret = dup2(pcb.sb.output_fd, STDOUT_FILENO);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1) {
			_exit(EXIT_FAILURE);
		}

		do {
			ret = dup2(pcb.sb.output_fd, STDERR_FILENO);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1) {
			_exit(EXIT_FAILURE);
		}

		bcd_io_fd_close(pcb.sb.output_fd);
	}

	sigemptyset(&emptyset);
	sigprocmask(SIG_SETMASK, &emptyset, NULL);

	if (bcd_config.oom_adjust)
		bcd_os_oom_adjust(&error);

	umask(bcd_config.umask);

	if ((bcd_config.flags & BCD_CONFIG_F_SETCOMM) &&
	    bcd_setcomm("[bcd] monitor") == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to respect BCD_CONFIG_F_SETCOMM", 0);
		_exit(EXIT_FAILURE);
	}

	if (asprintf(&bcd_target_process, "%ju",
	    (uintmax_t)pcb.sb.master_pid) == -1)
		goto fail;

	bcd_io_init(&error);

	bcd_pipe_ensure_readonly(&pcb.sb.master);
	bcd_pipe_ensure_writeonly(&pcb.sb.monitor);

	/*
	 * The tracer may use additional subprocesses to do asynchronous processing
	 * that doesn't need to prevent the tracee from exiting.  In the case of
	 * bcd_fatal especially we rely on the monitor exiting to close the pipe to
	 * signal the tracee to return from bcd_fatal.  The tracer itself doesn't need
	 * this pipe, we wait on the tracer process before exiting the monitor.
	 *
	 * However, without setting CLOEXEC the tracer's subprocesses can keep the
	 * pipe open, even if the tracer itself has exited.
	 */
	fcntl(pcb.sb.monitor.fd[1], F_SETFD, FD_CLOEXEC);

	listener = bcd_io_listener_unix(
	    bcd_config.ipc.us.path, 128, &error);
	if (listener == NULL)
		goto fail;

	if (bcd_chown(bcd_config.ipc.us.path, &error) == -1)
		goto fail;

	if (bcd_suid(&error) == -1)
		goto fail;

	if (bcd_io_listener_handler(listener, bcd_handler_accept,
	    bcd_handler_request_response,
	    sizeof(struct bcd_session), &error) == -1)
		goto fail;
	strlcpy(BCD_PACKET_PAYLOAD(&packet), bcd_config.ipc.us.path,
	    BCD_SB_PATH);

	r = bcd_sb_write(&pcb.sb.monitor, BCD_OP_CF,
	    BCD_PACKET(&packet), strlen(bcd_config.ipc.us.path) + 1,
	    0 /* wait forever */);
	if (r == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to write configuration information", errno);
		bcd_child_exit(EXIT_FAILURE);
	}

	event = bcd_io_event_create(pcb.sb.monitor.fd[1], bcd_handler_sb, 0,
	    &error);
	if (event == NULL) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to configure pipe watcher", errno);
		bcd_child_exit(EXIT_FAILURE);
	}

	if (bcd_io_event_add(event, BCD_IO_EVENT_CLOSE,
	    &error) == -1) {
		bcd_io_event_destroy(event);
		bcd_error(BCD_EVENT_FATAL, NULL, "failed to monitor pipe",
		    errno);
		bcd_child_exit(EXIT_FAILURE);
	}

	event = bcd_io_event_create(pcb.sb.master.fd[0], bcd_handler_fatal, 0,
	    &error);
	if (event == NULL) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to configure master pipe", errno);
		bcd_child_exit(EXIT_FAILURE);
	}

	if (bcd_io_event_add(event, BCD_IO_EVENT_READ | BCD_IO_EVENT_CLOSE,
	    &error) == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    "failed to watch master pipe", errno);
		bcd_io_event_destroy(event);
		bcd_child_exit(EXIT_FAILURE);
	}

	if (bcd_io_enter(&error) == -1) {
		bcd_error(BCD_EVENT_FATAL, NULL,
		    error.message, error.errnum);
		bcd_child_exit(EXIT_FAILURE);
	}

	bcd_child_exit(EXIT_SUCCESS);

fail:
	bcd_error(BCD_EVENT_FATAL, NULL, "failed to create UNIX socket", errno);
	_exit(EXIT_FAILURE);
}

static pid_t
bcd_os_fork(void)
{
	pid_t pid;
	sigset_t allmask, origmask;

	sigfillset(&allmask);
	sigprocmask(SIG_SETMASK, &allmask, &origmask);

	fflush(stdout);
	fflush(stderr);

	pid = fork();
	if (pid == 0) {
		bcd_child();
		_exit(EXIT_SUCCESS);
	}

	sigprocmask(SIG_SETMASK, &origmask, NULL);

	return pid;
}

int
bcd_associate_tid(const struct bcd *bcd, bcd_error_t *error, pid_t tid)
{
	pid_t *newtid;
	BCD_PACKET_INSTANCE(sizeof(*newtid)) packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;

	if (bcd->fd == -1) {
		bcd_error_set(error, errno,
		    "invalid fd; did you call bcd_attach?");
		return -1;
	}

	newtid = BCD_PACKET_PAYLOAD(&packet);
	*newtid = tid;

	BCD_PACKET(&packet)->op = BCD_OP_TID;

	r = bcd_packet_write(bcd->fd, BCD_PACKET(&packet), BCD_PACKET_SIZE(&packet),
	    timeout_abstime);
	if (r == -1) {
		bcd_error_set(error, errno, "failed to set new tid");
		return -1;
	}

	if (bcd_channel_read_ack(bcd->fd, timeout_abstime, error) != 0)
		return -1;

	return 0;
}

int
bcd_attach(struct bcd *bcd, bcd_error_t *error)
{
	struct sockaddr_un un;
	const socklen_t addrlen = sizeof(un);
	pid_t *tid;
	BCD_PACKET_INSTANCE(sizeof(*tid)) packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		bcd_error_set(error, errno,
		    "failed to create connection to monitor");
		goto fail;
	}

	memset(&un, 0, sizeof un);
	strlcpy(un.sun_path, pcb.sb.path, sizeof un.sun_path);
	un.sun_family = AF_UNIX;
        /* Designate usage of an abstract socket on Linux with @ */
#ifdef __linux__
        if (un.sun_path[0] == '@') {
                un.sun_path[0] = '\0';
        }
#endif

	for (;;) {
		int cr = connect(fd, (struct sockaddr *)&un, addrlen);
		if (cr == -1) {
			if (errno == EAGAIN)
				continue;

			bcd_error_set(error, errno,
			    "failed to connect to monitor");
			goto fail;
		}

		break;
	}

	if (bcd_io_fd_prepare(fd) == -1) {
		bcd_error_set(error, errno, "failed to create socket");
		bcd_io_fd_close(fd);
		return -1;
	}

	tid = BCD_PACKET_PAYLOAD(&packet);
	*tid = gettid();

	BCD_PACKET(&packet)->op = BCD_OP_TID;

	r = bcd_packet_write(fd, BCD_PACKET(&packet), BCD_PACKET_SIZE(&packet),
	    timeout_abstime);
	if (r == -1) {
		bcd_error_set(error, errno, "failed to initialize session");
		goto fail;
	}

	if (bcd_channel_read_ack(fd, timeout_abstime, error) != 0)
		goto fail; /* error will already be set */

	bcd->fd = fd;
	return 0;

fail:
	if (fd != -1) {
		bcd_io_fd_close(fd);
	}
	bcd->fd = -1;
	return -1;
}

int
bcd_detach(struct bcd *bcd, bcd_error_t *error)
{
	BCD_PACKET_INSTANCE(0) packet;
	ssize_t r;
	time_t timeout_abstime = bcd_os_time() + bcd_config.timeout;
	int ret, retval = 0;

	/* Succeed if we weren't attached. */
	if (bcd->fd == -1)
		return retval;

	/* Send exit operation to child. */
	BCD_PACKET(&packet)->op = BCD_OP_DETACH;

	r = bcd_packet_write(bcd->fd, BCD_PACKET(&packet), 0, timeout_abstime);
	if (r == -1) {
		bcd_error_set(error, errno,
		    "failed to cause monitor to detach");
		retval = -1;
		goto fail;
	}

	/* Wait for ack from child. */
	ret = bcd_channel_read_ack(bcd->fd, timeout_abstime, error);
	if (ret != 0) {
		/* error will already be set */
		retval = -1;
	}

fail:
	if (bcd->fd != -1)
		bcd_io_fd_close(bcd->fd);

	return retval;
}

int
bcd_init(const struct bcd_config *cf, bcd_error_t *error)
{
	BCD_PACKET_INSTANCE(BCD_SB_PATH) packet;
	struct bcd_sb *sb = &pcb.sb;
	pid_t child;
	ssize_t r;
	int ret;
	time_t timeout_abstime;

	if (cf == NULL) {
		bcd_config_latest_version_t default_config = {0};
		bcd_error_t noerror;

		ret = bcd_config_init_internal(
		    (struct bcd_config *)&default_config,
		    BCD_CONFIG_VERSION,
		    &noerror);
		assert(ret == 0);
		ret = bcd_config_assign(&default_config, &noerror);
		assert(ret == 0);
	} else {
		ret = bcd_config_assign(cf, error);
		if (ret != 0)
			return -1;
	}

	if (bcd_config.ipc.us.path == NULL) {
		char path[] = "/tmp/bcd.XXXXXX";
		char *buffer = NULL;
		int as = 0;

		if (mkdtemp(path) == NULL) {
			as = -1;
		} else {
			as = asprintf(&buffer, "%s/bcd.socket", path);
			if (as == -1)
				rmdir(path);

			unlink_directory = strdup(path);
			if (unlink_directory == NULL) {
				rmdir(path);
				free(buffer);
				bcd_error_set(error, 0,
				    "failed to generate UNIX socket directory");
				return -1;
			}
		}

		if (as == -1) {
			bcd_error_set(error, 0,
			    "failed to generate UNIX socket PATH");
			return -1;
		}

		bcd_config.ipc.us.path = buffer;
	}

	sb->output_fd = -1;
	if (bcd_config.invoke.output_file != NULL &&
	    bcd_config.invoke.output_file[0] != '\0') {
		do {
			ret = open(bcd_config.invoke.output_file,
			    O_CREAT | O_WRONLY | O_TRUNC,
			    S_IRUSR | S_IWUSR);
		} while (ret == -1 && errno == EINTR);
		if (ret == -1) {
			bcd_error_set(error, errno,
			    "failed to create output file");
			return -1;
		}
		sb->output_fd = ret;
	}

	sb->master_pid = getpid();

	if (bcd_pipe_init(&sb->monitor, error) == -1) {
		error->message = "failed to initialize monitor pipe";
		return -1;
	}

	if (bcd_pipe_init(&sb->master, error) == -1) {
		error->message = "failed to initialize master pipe";
		bcd_pipe_deinit(&sb->monitor);
		return -1;
	}

	child = bcd_os_fork();
	if (child == -1)
		goto fail;

	sb->monitor_pid = child;
	bcd_pipe_ensure_readonly(&sb->monitor);
	bcd_pipe_ensure_writeonly(&sb->master);

	/*
	 * After the child has spawned, wait for configuration information.
	 */
	timeout_abstime = bcd_os_time() + bcd_config.timeout;
	r = bcd_sb_read(&sb->monitor, BCD_PACKET(&packet), BCD_SB_PATH,
	    timeout_abstime, error);
	if (r == -1)
		goto fail;

	switch (BCD_PACKET(&packet)->op) {
	case BCD_OP_CF:
		strlcpy(sb->path, BCD_PACKET_PAYLOAD(&packet), BCD_SB_PATH);
		break;
	default:
		bcd_error_set(error, 0, "failed to initialize path");
		goto fail;
	}

	/*
	 * If all hell breaks loose, we assume we can rely on the
	 * control block section. Unfortunately, the clever person
	 * can still override protections.
	 */
#ifndef BCD_MPROTECT_OFF
	if (mprotect(sb, sizeof *sb, PROT_READ) == -1) {
		error->message = "failed to lock control page permissions";
		error->errnum = errno;
		goto fail;
	}
#endif /* !BCD_MPROTECT_OFF */

	return 0;

fail:
	bcd_pipe_deinit(&sb->monitor);
	bcd_pipe_deinit(&sb->master);
	return -1;
}
