#ifndef BCD_INTERNAL_CF_H
#define BCD_INTERNAL_CF_H

struct bcd_config_internal {
	/*
	 * Version of structure, used for ABI compatibility for configuration
	 * structure breaking changes.
	 */
	unsigned int version;

	/* These are currently unused. */
	unsigned long flags;

	/* If set, then protect preforked bcd process from OOM killer. */
	unsigned int oom_adjust;

	/* Asynchronous error handler, defaults to logging to stderr. */
	bcd_error_handler_t *handler;

	/*
	 * Maximum timeout associated with I/O events and tracer. Defaults
	 * to 30 seconds.
	 */
	unsigned int timeout;

	/* Default umask for file creation. */
	mode_t umask;

	/* Ownership of any created files. */
	struct {
		const char *user;
		const char *group;
	} chown;

	/* Credentials for runtime. */
	struct {
		const char *user;
		const char *group;
	} suid;

	/*
	 * Tracer configuration. Right now this relies on command-line options
	 * but can be extended (through path) to support pipes.
	 */
	struct {
		/* Base path is /opt/backtrace/bin/ptrace. */
		const char *path;

		/*
		 * Prefix for key-value options. For example, in ptrace
		 * it is "--kv=". If this is NULL, key-value pairs will
		 * be ignored.
		 */
		const char *kp;

		/*
		 * Separator between key-value pairs. If 0, then kp is
		 * repeated for every key-value pair. Default is ','.
		 */
		char separator;

		/* Seperator between key and value. Default is ':'. */
		char ks;

		/*
		 * Prefix for thread specifier. Defaults to "--thread=". If this
		 * is NULL, then only the process identifier is passed.
		 */
		const char *tp;

		/*
		 * File for redirected stdout/stderr output. If this is NULL or
		 * blank then the tracer outputs to the same stdout/stderr as
		 * the parent process.
		 */
		const char *output_file;
	} invoke;

	/*
	 * IPC mechanism for invoker monitor. The only supported mechanism
	 * at the moment is UNIX sockets.
	 */
	enum bcd_ipc ipc_mechanism;

	union {
		/* Configuration structure for UNIX socket. */
		struct {
			/*
			 * The path to the UNIX socket. If NULL, will evaluate
			 * to /tmp/bcd.<pid>.
			 */
			const char *path;
		} us;
	} ipc;

    /*
     * CPU and NUMA node affinity parameters
     */
    struct {
        /*
         * CPU to bind ourselves to. If -1, we don't bother setting our
         * affinity.
         */
        int target_cpu;
    } affinity;
};

extern struct bcd_config_internal bcd_config;

struct bcd_config_v1 {
	/*
	 * Version of structure, used for ABI compatibility for configuration
	 * structure breaking changes.
	 */
	unsigned int version;

	/* These are currently unused. */
	unsigned long flags;

	/* If set, then protect preforked bcd process from OOM killer. */
	unsigned int oom_adjust;

	/* Asynchronous error handler, defaults to logging to stderr. */
	bcd_error_handler_t *handler;

	/*
	 * Maximum timeout associated with I/O events and tracer. Defaults
	 * to 30 seconds.
	 */
	unsigned int timeout;

	/* Default umask for file creation. */
	mode_t umask;

	/* Ownership of any created files. */
	struct {
		const char *user;
		const char *group;
	} chown;

	/* Credentials for runtime. */
	struct {
		const char *user;
		const char *group;
	} suid;

	/*
	 * Tracer configuration. Right now this relies on command-line options
	 * but can be extended (through path) to support pipes.
	 */
	struct {
		/* Base path is /opt/backtrace/bin/ptrace. */
		const char *path;

		/*
		 * Prefix for key-value options. For example, in ptrace
		 * it is "--kv=". If this is NULL, key-value pairs will
		 * be ignored.
		 */
		const char *kp;

		/*
		 * Separator between key-value pairs. If 0, then kp is
		 * repeated for every key-value pair. Default is ','.
		 */
		char separator;

		/* Seperator between key and value. Default is ':'. */
		char ks;

		/*
		 * Prefix for thread specifier. Defaults to "--thread=". If this
		 * is NULL, then only the process identifier is passed.
		 */
		const char *tp;

		/*
		 * File for redirected stdout/stderr output. If this is NULL or
		 * blank then the tracer outputs to the same stdout/stderr as
		 * the parent process.
		 */
		const char *output_file;
	} invoke;

	/*
	 * IPC mechanism for invoker monitor. The only supported mechanism
	 * at the moment is UNIX sockets.
	 */
	enum bcd_ipc ipc_mechanism;

	union {
		/* Configuration structure for UNIX socket. */
		struct {
			/*
			 * The path to the UNIX socket. If NULL, will evaluate
			 * to /tmp/bcd.<pid>.
			 */
			const char *path;
		} us;
	} ipc;

    /*
     * CPU and NUMA node affinity parameters
     */
    struct {
        /*
         * Target CPU core to migrate bcd to. If set to -1, the CPU affinity
         * is unmodified.
         */
        int target_cpu;
    } affinity;
};

typedef struct bcd_config_v1 bcd_config_latest_version_t;

/*
 * Initializes a bcd_config configuration struct based on the specified version.
 */
#ifndef BCD_AMALGAMATED
int bcd_config_init_internal(struct bcd_config *,
    unsigned int, bcd_error_t *);
#endif

/*
 * Assigns a versioned configuration to our internal configuration.
 */
int bcd_config_assign(const void *, struct bcd_error *);


#endif /* BCD_INTERNAL_CF_H */
