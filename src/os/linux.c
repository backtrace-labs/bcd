#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

int
bcd_setcomm(const char *title)
{

	/* Linux requires comm to be <= 16 bytes, including the terminator. */
	if (title == NULL || *title == '\0' || strlen(title) > 15)
		return -1;

	return prctl(PR_SET_NAME, title);
}

int
bcd_set_cpu_affinity(int core_id)
{
	pid_t pid = getpid();
	cpu_set_t cpuset;

	if (0 > core_id) {
		return -1;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);

	if (-1 == sched_setaffinity(pid, sizeof(cpuset), &cpuset)) {
        return -1;
	}

	return 0;
}

time_t
bcd_os_time(void)
{
#if defined(_POSIX_TIMERS) && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		bcd_abort();

	return ts.tv_sec;
#else
#warning Crash reporting may be affected by wallclock reset.
	return time(NULL);
#endif /* !_POSIX_TIMERS || !_POSIX_MONOTONIC_CLOCK */
}

int
bcd_os_oom_adjust(bcd_error_t *error)
{
	char path[PATH_MAX];
	pid_t pid = getpid();
	const char *const score = "-17";
	size_t score_length = strlen(score);
	ssize_t ac = 0;
	int r, fd, i;

	r = snprintf(path, sizeof(path), "/proc/%ju/oom_adj",
	    (uintmax_t)pid);

	for (i = 0;; i++) {
		if (r < 0 || (size_t)r >= sizeof path) {
			bcd_error_set(error, 0, "failed to construct oom path");
			return -1;
		}

		fd = open(path, O_WRONLY);
		if (fd == -1) {
			if (errno != EEXIST || i > 1) {
				bcd_error_set(error, errno,
				    "failed to open oom path");
				return -1;
			}

			r = snprintf(path, sizeof(path),
			    "/proc/%ju/oom_score_adj", (uintmax_t)pid);
			continue;
		}

		break;
	}

	do {
		ssize_t wr = write(fd, score, score_length);

		if (wr == -1) {
			if (errno == EINTR)
				continue;

			bcd_error_set(error, errno, "failed to adjust OOM score");
			goto fail;
		}

		ac += wr;
	} while ((size_t)ac < score_length);

	bcd_io_fd_close(fd);
	return 0;

fail:
	bcd_io_fd_close(fd);
	return -1;
}
#endif /* __linux__ */
