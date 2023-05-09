#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#ifdef BCD_F_PRELOAD
#include <dlfcn.h>

static __sighandler_t (*real_signal)(int, __sighandler_t);
static int (*real_sigaction)(int, const struct sigaction *,
    struct sigaction *);

/*
 * Defines behavior for handling other signal handlers:
 * - -1: uninitialized state.
 * - 0 [default]: Allow replacing of libbcd handlers.
 * - 1: Ignore other handlers entirely.
 */
static sig_atomic_t signal_override = -1;

static bool
handled(const int s)
{
	static int ignore_signals[] = {
	    SIGSEGV,
	    SIGFPE,
	    SIGABRT,
	    SIGBUS,
	    SIGILL,
	    SIGFPE
	};
	size_t i;
	bool h = false;

	if (signal_override == 0)
		return false;

	for (i = 0; h == false && i < sizeof(ignore_signals) /
	    sizeof(*ignore_signals); i++) {
		h = ignore_signals[i] == s;
	}

	if (h == true && signal_override == 1)
		fprintf(stderr, "[BCD] Ignoring handler for signal %d\n", s);

	return h;
}

__sighandler_t
signal(int signum, __sighandler_t handler)
{

	if (handled(signum) == false)
		return real_signal(signum, handler);

	return NULL;
}

int
sigaction(int signum, const struct sigaction *sa, struct sigaction *oldsa)
{

	if (handled(signum) == false)
		return real_sigaction(signum, sa, oldsa);

	return 0;
}

static void
string_from_env(const char **output, const char *variable)
{
	char *value;

	value = getenv(variable);
	if (value != NULL && *value != '\0')
		*output = value;

	return;
}

static void
char_from_env(char *output, const char *variable)
{
	char *value;

	value = getenv(variable);
	if (value != NULL && *value != '\0')
		*output = *value;

	return;
}

static void
bcd_config_from_env(struct bcd_config *cf)
{
	char *value;

	value = getenv("BCD_OOM_ADJUST");
	if (value != NULL && strcmp(value, "1") == 1)
		cf->oom_adjust = 1;

	string_from_env(&cf->invoke.path, "BCD_INVOKE_PATH");
	string_from_env(&cf->invoke.kp, "BCD_INVOKE_KP");
	char_from_env(&cf->invoke.separator, "BCD_INVOKE_SEPARATOR");
	char_from_env(&cf->invoke.ks, "BCD_INVOKE_KS");
	string_from_env(&cf->invoke.tp, "BCD_INVOKE_TP");
	string_from_env(&cf->invoke.output_file, "BCD_INVOKE_OUTPUT_FILE");

	string_from_env(&cf->ipc.us.path, "BCD_IPC_US_PATH");
	return;
}

static void __attribute__((constructor))
bcd_preload(void)
{
	struct bcd_config config;
	bcd_error_t error;
	bcd_t bcd;
	const char *enabled = getenv("BCD_PRELOAD");
	const char *reraise = getenv("BCD_RAISE");
	const char *override = getenv("BCD_SIGNAL_OVERRIDE");
	void *p;
	unsigned int flags = 0;
	int r;

	p = dlsym(RTLD_NEXT, "signal");
	real_signal = p;

	p = dlsym(RTLD_NEXT, "sigaction");
	real_sigaction = p;

	if (enabled == NULL)
		return;

	if (override != NULL) {
		if (override[0] != '\0' && override[1] == '\0')
			signal_override = override[0] - '0';

		switch (signal_override) {
		case 0:
			break;
		case 1:
			fprintf(stderr, "[BCD] Ignoring external signal handlers\n");
			break;
		default:
			fprintf(stderr, "[BCD] Ignoring invalid "
			    "BCD_SIGNAL_OVERRIDE='%s'\n", override);
			signal_override = 0;
			break;
		}
	}
	if (signal_override < 0)
		signal_override = 0;

	if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) == -1)
		perror("prctl");

	fprintf(stderr, "[BCD] Initializing BCD...\n");

	/* Initialize BCD configuration. See bcd.h for options */
	if (bcd_config_init(&config, &error) == -1)
		exit(EXIT_FAILURE);

	bcd_config_from_env(&config);

	/* Initialize the library. */
	if (bcd_init(&config, &error) == -1)
		exit(EXIT_FAILURE);

	/* Initialize a handle to BCD. */
	if (bcd_attach(&bcd, &error) == -1)
		exit(EXIT_FAILURE);

	if (reraise != NULL && strcmp(reraise, "1") == 0)
		flags |= BCD_SIGACTION_RAISE;

	r = bcd_sigaction_internal(NULL, flags, real_sigaction);
	if (r != 0) {
		fprintf(stderr, "[BCD] failed to register handler for %d: %d\n",
		    r, errno);
	}
	return;
}
#endif /* BCD_F_PRELOAD */
