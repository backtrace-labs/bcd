#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

#ifdef BCD_F_PRELOAD
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

static void
signal_handler(int s, siginfo_t *si, void *unused)
{

	(void)unused;
	(void)si;

	bcd_fatal("Fatal signal received.");

	signal(s, SIG_DFL);
	raise(s);
	return;
}

static void
bcd_preload_sigaction(void)
{
	struct sigaction sa;
	int signals[] = {
		SIGSEGV,
		SIGFPE,
		SIGABRT,
		SIGBUS,
		SIGILL,
		SIGFPE
	};

	sa.sa_sigaction = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

	for (size_t i = 0; i < sizeof(signals) / sizeof(*signals); i++) {
		if (sigaction(signals[i], &sa, NULL) == -1) {
			fprintf(stderr, "warning: failed to set signal "
			    "handler %d\n", signals[i]);
		}
	}

	return;
}

static void __attribute__((constructor))
bcd_preload(void)
{
	struct bcd_config config;
	bcd_error_t error;
	bcd_t bcd;
	const char *enabled = getenv("BCD_PRELOAD");

	if (enabled == NULL)
		return;

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

	bcd_preload_sigaction();
	return;
}
#endif /* BCD_F_PRELOAD */
