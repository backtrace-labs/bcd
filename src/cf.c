#include <assert.h>
#include <string.h>

#ifndef BCD_AMALGAMATED
#include "internal.h"
#endif /* !BCD_AMALGAMATED */

struct bcd_config_internal bcd_config;

static void
bcd_config_init_v1(struct bcd_config_v1 *cf)
{

	cf->version = 1;
	cf->oom_adjust = 1;
	cf->handler = bcd_error_handler_default;
	cf->timeout = 30;
	cf->umask = 0177;
	cf->affinity.target_cpu = -1;
	memset(&cf->chown, 0, sizeof cf->chown);
	memset(&cf->suid, 0, sizeof cf->chown);

	cf->invoke.path = "/opt/backtrace/bin/ptrace";
	cf->invoke.kp = "--kv=";
	cf->invoke.separator = ',';
	cf->invoke.ks = ':';
	cf->invoke.tp = "--thread=";
	cf->invoke.output_file = NULL;

	cf->ipc_mechanism = BCD_IPC_UNIX_SOCKET;
	memset(&cf->ipc, 0, sizeof cf->ipc);
}

static int
bcd_config_assign_from_v1(const void *cfv, struct bcd_error *e)
{
	const struct bcd_config_v1 *cf = (const struct bcd_config_v1 *)cfv;

	assert(cf->version == 1);
	(void)e;

	bcd_config.version = cf->version;
	bcd_config.flags = cf->flags;
	bcd_config.oom_adjust = cf->oom_adjust;
	bcd_config.handler = cf->handler;
	bcd_config.timeout = cf->timeout;
	bcd_config.umask = cf->umask;
	bcd_config.chown.user = cf->chown.user;
	bcd_config.chown.group = cf->chown.group;
	bcd_config.suid.user = cf->suid.user;
	bcd_config.suid.group = cf->suid.group;
	bcd_config.invoke.path = cf->invoke.path;
	bcd_config.invoke.kp = cf->invoke.kp;
	bcd_config.invoke.separator = cf->invoke.separator;
	bcd_config.invoke.ks = cf->invoke.ks;
	bcd_config.invoke.tp = cf->invoke.tp;
	bcd_config.invoke.output_file = cf->invoke.output_file;
	bcd_config.ipc_mechanism = cf->ipc_mechanism;
	bcd_config.ipc.us.path = cf->ipc.us.path;
	bcd_config.affinity.target_cpu = cf->affinity.target_cpu;

	return 0;
}

int
bcd_config_init_internal(struct bcd_config *cf, unsigned int caller_version,
    bcd_error_t *e)
{

	switch (caller_version) {
	case 1:
		bcd_config_init_v1((struct bcd_config_v1 *)cf);
		return 0;
	default:
		bcd_error_set(e, 0, "unrecognized config version");
	}

	return -1;
}

int
bcd_config_assign(const void *cf, struct bcd_error *e)
{
	/* All versions of bcd_config must start with unsigned int version. */
	const struct bcd_config *bcd_cf = cf;

	switch (bcd_cf->version) {
	case 1:
		return bcd_config_assign_from_v1(cf, e);
	default:
		bcd_error_set(e, 0, "unrecognized config version");
	}

	return -1;
}

