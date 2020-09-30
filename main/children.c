/*
gridinit-utils, a helper library for gridinit.
Copyright (C) 2013 AtoS Worldline, original work aside of Redcurrant
Copyright (C) 2015-2018 OpenIO SAS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>

#include "./gridinit-utils.h"

time_t supervisor_default_delay_KILL = SUPERVISOR_DEFAULT_TIMEOUT_KILL;

static time_t _monotonic_seconds(void) {
	return g_get_monotonic_time() / G_TIME_SPAN_SECOND;
}

/**
 * Temporary flag used by gridinit to mark services during a refresh.
 */
#define MASK_OBSOLETE     0x01

/**
 * The service has been explicitely disabled and won't be restarted
 */
#define MASK_DISABLED     0x02

/**
 * This flag tells the service must be restarted when it falls
 */
#define MASK_RESPAWN      0x04

/**
 * The service has been started and should be running
 */
#define MASK_STARTED      0x08

/**
 * The service died too often and won't be automatically restarted
 * unless it is explicitely reset
 */
#define MASK_BROKEN       0x10

/**
 * Should the service be considered dead when it dies too often?
 */
#define MASK_NEVER_BROKEN 0x20

/**
 * Tells if the child should be immediately restarted or not
 */
#define MASK_DELAYED      0x40

/**
 * Tells if the child should restart after explicitely being stopped
 */
#define MASK_RESTART	  0x80

#define FLAG_SET(sd,M) do { sd->flags |= (M); } while (0)
#define FLAG_DEL(sd,M) do { sd->flags &= ~(M); } while (0)
#define FLAG_HAS(sd,M) (sd->flags & (M))

#define FOREACH_CHILD(sd) for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next)

struct my_rlimits_s {
	gint64 core_size;
	gint64 stack_size;
	gint64 nb_files;
};

struct child_s {
	struct child_s *next;
	time_t delay_before_KILL;
	gchar *command;
	pid_t pid;
	uid_t uid;
	gid_t gid;
	gchar *working_directory;
	guint8 flags; /* internal use only */
	guint32 user_flags;
	GSList *env;

	/* Useful stats */
	guint counter_started;
	guint counter_died;

	/* wall-clock time */
	time_t last_start;

	/* monotonic-clock time */
	time_t last_start_attempt;
	time_t first_kill_attempt;
	time_t last_kill_attempt;

	struct {
		time_t t0;
		time_t t1;
		time_t t2;
		time_t t3;
		time_t t4;
	} deaths;

	/* Child's startup properties */
	struct my_rlimits_s rlimits;

	gchar key[SUPERVISOR_LIMIT_CHILDKEYSIZE];
	gchar group[2048];
};

static struct child_s SRV_BEACON = {};


static struct child_s *
supervisor_get_child(const gchar *key)
{
	struct child_s *sd;

	FOREACH_CHILD(sd) {
		if (0 == g_ascii_strcasecmp(sd->key, key))
			return sd;
	}

	return NULL;
}

static void
_child_reset_deaths(struct child_s *sd)
{
	sd->deaths.t4 = 0L;
	sd->deaths.t3 = 0L;
	sd->deaths.t2 = 0L;
	sd->deaths.t1 = 0L;
}

static int
_child_set_flag(struct child_s *sd, guint32 mask, gboolean enabled)
{
	errno = 0;
	if (enabled) {

		if (mask & MASK_STARTED) {
			sd->last_start_attempt = 0;
			_child_reset_deaths(sd);
		}

		if (FLAG_HAS(sd,mask))
			return 0;
		FLAG_SET(sd,mask);
		return 1;
	}
	else {
		if (mask & MASK_STARTED) {
			sd->first_kill_attempt = 0;
			sd->last_kill_attempt = 0;
			_child_reset_deaths(sd);
		}
	}

	if (!FLAG_HAS(sd,mask))
		return 0;
	FLAG_DEL(sd,mask);
	return 1;
}

static int
supervisor_children_set_flag(const char *key, guint32 mask, gboolean enabled)
{
	struct child_s *sd;

	if (!key) {
		errno = EINVAL;
		return -1;
	}
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}
	if (FLAG_HAS(sd,MASK_OBSOLETE)) {
		errno = ENOENT;
		return -1;
	}

	return _child_set_flag(sd, mask, enabled);
}

static long
i64tolong(gint64 i64)
{
	long l;
	if (i64 >= G_MAXLONG)
		return G_MAXLONG;
	if (i64 < 0)
		return -1L;
	l = i64;
	return l;
}

static void
_child_get_info(struct child_s *c, struct child_info_s *ci)
{
	memset(ci, 0x00, sizeof(*ci));
	ci->key = c->key;
	ci->cmd = c->command;
	ci->enabled = !FLAG_HAS(c,MASK_DISABLED);
	ci->started = FLAG_HAS(c,MASK_STARTED);
	ci->respawn = FLAG_HAS(c,MASK_RESPAWN);
	ci->broken = FLAG_HAS(c,MASK_BROKEN);
	ci->breakable = !FLAG_HAS(c,MASK_NEVER_BROKEN);
	ci->user_flags = c->user_flags;
	ci->pid = c->pid;
	ci->uid = c->uid;
	ci->gid = c->gid;
	ci->counter_started = c->counter_started;
	ci->counter_died = c->counter_died;
	ci->last_start_attempt = c->last_start;

	ci->rlimits.core_size = i64tolong(c->rlimits.core_size);
	ci->rlimits.stack_size = i64tolong(c->rlimits.stack_size);
	ci->rlimits.nb_files = i64tolong(c->rlimits.nb_files);

	ci->group = c->group;
}

static void
sighandler_NOOP(int s)
{
	signal(s, sighandler_NOOP);
}

static void
reset_sighandler(void)
{
	signal(SIGQUIT, sighandler_NOOP);
	signal(SIGTERM, sighandler_NOOP);
	signal(SIGINT,  sighandler_NOOP);
	signal(SIGPIPE, sighandler_NOOP);
	signal(SIGUSR1, sighandler_NOOP);
	signal(SIGUSR2, sighandler_NOOP);
	signal(SIGCHLD, sighandler_NOOP);
}

static guint
_wait_for_dead_child(pid_t *ptr_pid)
{
	register pid_t pid, pid_exited;

	if ((pid = *ptr_pid) <= 0)
		return 0;

	errno = 0;
	pid_exited = waitpid(pid, NULL, WNOHANG);
	if (pid_exited>0 || errno==ECHILD) {
		*ptr_pid = 0;
		return 1;
	}

	return 0;
}

static void
_child_set_rlimits(struct my_rlimits_s *new_limits, struct my_rlimits_s *save)
{
	save->stack_size = save->nb_files = save->core_size = G_MAXINT64;

	(void) supervisor_limit_get(SUPERV_LIMIT_THREAD_STACK, &(save->stack_size));
	(void) supervisor_limit_get(SUPERV_LIMIT_MAX_FILES,    &(save->nb_files));
	(void) supervisor_limit_get(SUPERV_LIMIT_CORE_SIZE,    &(save->core_size));

	(void) supervisor_limit_set(SUPERV_LIMIT_THREAD_STACK, new_limits->stack_size);
	(void) supervisor_limit_set(SUPERV_LIMIT_MAX_FILES,    new_limits->nb_files);
	(void) supervisor_limit_set(SUPERV_LIMIT_CORE_SIZE,    new_limits->core_size);
}

static void
_child_restore_rlimits(struct my_rlimits_s *save)
{
	(void) supervisor_limit_set(SUPERV_LIMIT_THREAD_STACK, save->stack_size);
	(void) supervisor_limit_set(SUPERV_LIMIT_MAX_FILES,    save->nb_files);
	(void) supervisor_limit_set(SUPERV_LIMIT_CORE_SIZE,    save->core_size);
}

static void
my_clear_env(void)
{
	gchar **old_env, **e;
	old_env = g_listenv();
	if (old_env) {
		for (e=old_env; *e ;e++)
			g_unsetenv(*e);
		g_strfreev(old_env);
	}
}

/**
 * Must be called after the fork, from the child, just before the execve
 */
static char **
_child_build_env(struct child_s *sd)
{
	int i;
	char **new_env;
	GSList *l;
	gchar *s, *k, *v;

	my_clear_env();

	new_env = calloc(1 + g_slist_length(sd->env), sizeof(char*));

	/* Run the configured environment */
	for (i=0, l=sd->env; l && l->next ;l=l->next->next) {
		k = l->data;
		v = l->next->data;
		if (!k || !v)
			continue;

		/* set the current env ... */
		if (!g_setenv(k, v, TRUE))
			WARN("g_setenv(%s,%s) error : %s", k, v, strerror(errno));

		/* ... and prepare the child's env */
		s = g_strdup_printf("%s=%s", k, v);
		new_env[i++] = strdup(s);
		g_free(s);
		TRACE("[%s] setenv(%s,%s)", sd->key, k, v);
	}

	return new_env;
}

static void
_child_exec(struct child_s *sd, int argc, char ** args)
{
	char **env;
	const gchar *cmd = args[0];
	gchar *real_cmd = NULL;

	(void) argc;
	/* If the target command is just a filename, then try to find
	 * it in the PATH that could have been set for this command */
	env = _child_build_env(sd);

	/* JFS: No need to free the allocated memory of gridinit, execve will do. */
	/* supervisor_children_cleanall(); */

	/* JFS: the internal sockets of libdill do not carry the O_CLOEXEC flag.
	 *      We want to avoid any FD leak to the children. */
	for (int i=3; i<8; i++)
		close(i);

	if (g_path_is_absolute(cmd))
		real_cmd = g_strdup(cmd);

	if (!real_cmd && NULL == (real_cmd = g_find_program_in_path(cmd)))
		FATAL("'%s' not executable or not found in PATH:%s", cmd, g_getenv("PATH"));
	else {
		execve(real_cmd, args, env);
		FATAL("exec failed : errno=%d %s", errno, strerror(errno));
	}
}

/**
 * @return <li>-1 when the fork failed;<li>0 when the service does not meet the
 * conditions to start;<li>1 when the service has been forked successfuly.
 */
static gint
_child_start(struct child_s *sd, void *udata, supervisor_cb_f cb)
{
	typeof(errno) errsav;
	gint argc;
	gchar **args;
	struct my_rlimits_s saved_limits = {};

	if (!sd || !sd->command) {
		errno = EINVAL;
		return -1;
	}

	if (!g_shell_parse_argv(sd->command, &argc, &args, NULL)) {
		errno = EINVAL;
		return -1;
	}

	sd->last_start_attempt = _monotonic_seconds();
	sd->last_start = time(0);

	_child_set_rlimits(&(sd->rlimits), &saved_limits);
	sd->pid = fork();

	switch (sd->pid) {

	case -1: /* error */
		errsav = errno;
		g_strfreev(args);
		errno = errsav;
		return -1;

	case 0: /* child */
		setsid();
		sd->pid = getpid();
		reset_sighandler();

		/* change the rights before changing the working directory */
		if (getuid() == 0) {
			setgid(sd->gid);
			setuid(sd->uid);
		}
		if (sd->working_directory)
			chdir(sd->working_directory);

		_child_exec(sd, argc, args);
		exit(-1);
		return 0; /* makes everybody happy */

	default: /* father */

		INFO("Starting service [%s] with pid %i", sd->key, sd->pid);

		if (cb) {
			struct child_info_s ci;
			_child_get_info(sd, &ci);
			cb(udata, &ci);
		}

		_child_restore_rlimits(&saved_limits);

		DEBUG("set limits (%"G_GINT64_FORMAT",%"G_GINT64_FORMAT",%"G_GINT64_FORMAT")"
			" then restored (%"G_GINT64_FORMAT",%"G_GINT64_FORMAT",%"G_GINT64_FORMAT") (stack,file,core)"
			, sd->rlimits.stack_size, sd->rlimits.nb_files, sd->rlimits.core_size
			, saved_limits.stack_size, saved_limits.nb_files, saved_limits.core_size);

		FLAG_DEL(sd,MASK_BROKEN);
		sd->counter_started ++;
		errsav = errno;
		g_strfreev(args);
		errno = errsav;
		return 0;
	}
}

static void
_child_stop(struct child_s *sd)
{
	if (sd->pid > 0) {
		time_t now = _monotonic_seconds();
		if (sd->first_kill_attempt == 0)
			sd->first_kill_attempt = now;
		if (sd->delay_before_KILL > 0
				&& sd->first_kill_attempt > 0
				&& (now - sd->first_kill_attempt) > sd->delay_before_KILL) {
			DEBUG("Service [%s] did not exit after 60s, sending SIGKILL", sd->key);
			kill(sd->pid, SIGKILL);
		} else {
			DEBUG("Sending SIGTERM to service [%s] pid %i", sd->key, sd->pid);
			kill(sd->pid, SIGTERM);
		}
		sd->last_kill_attempt = now;
	}
}

static void
_child_notify_death(struct child_s *sd)
{
	if (FLAG_HAS(sd, MASK_RESTART))
		return;

	sd->counter_died ++;
	sd->deaths.t4 = sd->deaths.t3;
	sd->deaths.t3 = sd->deaths.t2;
	sd->deaths.t2 = sd->deaths.t1;
	sd->deaths.t1 = sd->deaths.t0;
	sd->deaths.t0 = _monotonic_seconds();

	if (FLAG_HAS(sd, MASK_NEVER_BROKEN))
		return;

	if (sd->deaths.t4) {
		if ((sd->deaths.t0 - sd->deaths.t4) < 60L)
			FLAG_SET(sd, MASK_BROKEN);
	}
}

static inline gboolean
_child_should_be_up(struct child_s *sd)
{
	return !(FLAG_HAS(sd,MASK_BROKEN) || FLAG_HAS(sd,MASK_DISABLED) || FLAG_HAS(sd,MASK_OBSOLETE))
		&& FLAG_HAS(sd, MASK_STARTED);
}

static void
_child_debug(struct child_s *sd, const gchar *tag)
{
	time_t now = _monotonic_seconds();
	DEBUG("%s [%s] flags=%04X now=%ld deaths{%ld,%ld,%ld,%ld,%ld}",
		tag, sd->key, sd->flags, now,
		now - sd->deaths.t0,
		now - sd->deaths.t1,
		now - sd->deaths.t2,
		now - sd->deaths.t3,
		now - sd->deaths.t4);
}

static gboolean
_child_can_be_restarted(struct child_s *sd)
{
	if (!_child_should_be_up(sd))
		return FALSE;

	if (!sd->last_start_attempt)
		return TRUE;

	/* here : already been started */
	if (!FLAG_HAS(sd,MASK_RESPAWN))
		return FALSE;

	/* here : restart allowed */
	if (!FLAG_HAS(sd,MASK_DELAYED))
		return TRUE;

	/* here : restart delayed if died too early */
	time_t now = _monotonic_seconds();

	_child_debug(sd, "DEAD");

	if (sd->deaths.t4 && (now - sd->deaths.t4)<=16L) {
		DEBUG("death 4 too close (%ld <= 16L)", (now - sd->deaths.t4));
		return FALSE;
	}
	if (sd->deaths.t3 && (now - sd->deaths.t3)<=8L) {
		DEBUG("death 3 too close (%ld <= 8L)", (now - sd->deaths.t3));
		return FALSE;
	}
	if (sd->deaths.t2 && (now - sd->deaths.t2)<=4L) {
		DEBUG("death 2 too close (%ld <= 4L)", (now - sd->deaths.t2));
		return FALSE;
	}
	if (sd->deaths.t1 && (now - sd->deaths.t1)<=2L) {
		DEBUG("death 1 too close (%ld <= 2L)", (now - sd->deaths.t1));
		return FALSE;
	}

	return TRUE;
}

/* Public API -------------------------------------------------------------- */

int
supervisor_children_get_info(const gchar *key, struct child_info_s *ci)
{
	struct child_s *sd;

	if (!key || !ci || !*key) {
		errno= EINVAL;
		return -1;
	}

	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	_child_get_info(sd, ci);
	errno = 0;
	return 0;
}

guint
supervisor_children_killall(int sig)
{
	guint count;
	struct child_s *sd;

	count = 0;
	FOREACH_CHILD(sd) {
		if (sd->pid > 0) {
			if (0 == kill(sd->pid, sig))
				count ++;
		}
	}

	return count;
}

guint
supervisor_children_start_enabled(void *udata, supervisor_cb_f cb)
{
	guint count, proc_count;
	struct child_s *sd;

	count = proc_count = 0U;
	FOREACH_CHILD(sd) {

		proc_count ++;

		if (sd->pid > 0) {
			if (1U == _wait_for_dead_child(&(sd->pid)))
				_child_notify_death(sd);
		}

		if (sd->pid <= 0) {
			if (FLAG_HAS(sd, MASK_RESTART))
				_child_set_flag(sd, MASK_STARTED, TRUE);

			if (_child_can_be_restarted(sd)) {
				if (0 == _child_start(sd, udata, cb))
					count ++;
				FLAG_DEL(sd, MASK_RESTART);
			}
		}
	}

	return count;
}

guint
supervisor_children_mark_obsolete(void)
{
	guint count;
	struct child_s *sd;

	count = 0;
	FOREACH_CHILD(sd) {
		FLAG_SET(sd, MASK_OBSOLETE);
		count ++;
	}

	return count;
}

guint
supervisor_children_disable_obsolete(void)
{
	guint count;
	struct child_s *sd;

	count = 0U;
	FOREACH_CHILD(sd) {
		if (FLAG_HAS(sd,MASK_OBSOLETE)) {
			FLAG_SET(sd, MASK_DISABLED);
			count ++;
		}
	}

	return count;
}

static inline int
_is_dead(const pid_t needle, pid_t *pincushion, register const int max)
{
	for (register int i=0; i<max ;++i) {
		if (needle == pincushion[i])
			return 1;
	}
	return 0;
}

guint
supervisor_children_catharsis(void *udata, supervisor_cb_f cb)
{
	struct child_s *sd;
	guint count = 0;
	int pids_idx = 0;
	pid_t pid;
	pid_t pids[1024];

	g_assert_nonnull(cb);

	/* Consume a batch of dead children */
	while (pids_idx < 1024 && (pid = waitpid(-1, NULL, WNOHANG)) > 0)
		pids[pids_idx++] = pid;
	if (!pids_idx)
		return 0;

	/* Locate the concerned structures, for each dead child */
	FOREACH_CHILD(sd) {
		if (!_is_dead(sd->pid, pids, pids_idx))
			continue;

		count++;
		_child_notify_death(sd);

		struct child_info_s ci = {};
		_child_get_info(sd, &ci);
		cb(udata, &ci);

		sd->pid = -1;
	}

	return count;
}

void
supervisor_children_stopall(guint max_retries)
{
	guint retries;

	struct child_s *sd;
	FOREACH_CHILD(sd) {
		FLAG_DEL(sd, MASK_STARTED);
	}

	for (retries=0; max_retries<=0 || retries<max_retries ;retries++) {
		if (!supervisor_children_killall(SIGTERM))
			return;
		sleep(1);
	}
}

guint
supervisor_children_cleanall(void)
{
	struct child_s *sd, *sd_next;
	guint count;

	count = 0;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd_next) {
		sd_next = sd->next;

		if (sd->command)
			g_free(sd->command);
		if (sd->working_directory)
			g_free(sd->working_directory);

		memset(sd, 0x00, sizeof(struct child_s));
		g_free(sd);
		count ++;
	}
	SRV_BEACON.next = &SRV_BEACON;

	return count;
}

void
supervisor_children_init(void)
{
	SRV_BEACON.next = &SRV_BEACON;
}

void
supervisor_children_fini(void)
{
	/* nothing to do yet */
}


gboolean
supervisor_children_register(const gchar *key, const gchar *cmd)
{
	struct child_s *sd = NULL;

	/* check if the service is present */
	FOREACH_CHILD(sd) {
		if (0 == g_ascii_strcasecmp(sd->key, key)) {

			/* the command might have changed */
			if (sd->command)
				g_free(sd->command);
			sd->command = g_strdup(cmd);

			FLAG_DEL(sd,MASK_OBSOLETE);
			return TRUE;
		}
	}

	/* Child not found, it will be created */
	sd = g_try_malloc0(sizeof(struct child_s));
	if (NULL == sd) {
		errno = ENOMEM;
		return FALSE;
	}

	g_strlcpy(sd->key, key, sizeof(sd->key));
	sd->delay_before_KILL = supervisor_default_delay_KILL;
	sd->flags = MASK_STARTED|MASK_RESPAWN|MASK_DELAYED;
	sd->working_directory = g_get_current_dir();
	sd->command = g_strdup(cmd);
	sd->pid = 0;
	sd->uid = getuid();
	sd->gid = getgid();

	/* set the system limits to the current values */
	sd->rlimits.core_size = -1;
	sd->rlimits.stack_size = 1024 * 1024;
	sd->rlimits.nb_files = 32768;
	(void) supervisor_limit_get(SUPERV_LIMIT_THREAD_STACK, &(sd->rlimits.stack_size));
	(void) supervisor_limit_get(SUPERV_LIMIT_MAX_FILES,    &(sd->rlimits.nb_files));
	(void) supervisor_limit_get(SUPERV_LIMIT_CORE_SIZE,    &(sd->rlimits.core_size));

	/* ring insertion */
	sd->next = SRV_BEACON.next;
	SRV_BEACON.next = sd;

	return TRUE;
}

gint
supervisor_run_services(void *udata, supervisor_run_cb_f callback)
{
	gint count = 0U;

	g_assert_nonnull(callback);

	struct child_s *sd;
	FOREACH_CHILD(sd) {
		struct child_info_s ci = {};
		if (FLAG_HAS(sd, MASK_OBSOLETE))
			continue;
		_child_get_info(sd, &ci);
		if (callback(udata, &ci)) {
			count++;
		}
	}

	return count;
}

guint
supervisor_children_kill_disabled(void)
{
	guint count = 0U;

	struct child_s *sd;
	FOREACH_CHILD(sd) {
		/* Stop child that needs to be restarted */
		if (FLAG_HAS(sd,MASK_RESTART))
			_child_set_flag(sd, MASK_STARTED, FALSE);

		if (!_child_should_be_up(sd)) {
			if (sd->pid > 0) {
				_child_stop(sd);
				_wait_for_dead_child(&(sd->pid));
				count ++;
			}
		}
	}

	return count;
}

int
supervisor_children_enable(const char *key, gboolean enable)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}
	if (FLAG_HAS(sd,MASK_OBSOLETE)) {
		errno = ENOENT;
		return -1;
	}

	if (!enable) {
		/* If the process is being disabled, there is no need to
		 * keep the BROKEN flag. This flag would survive a later
		 * re-enabling of the process... */
		_child_set_flag(sd, MASK_BROKEN, FALSE);

		/* We reset the 'last_start_attempt' field. This is necessary
		 * to explicitely restart services configured with the 'cry'
		 * value for their 'on_die' parameter */
		sd->last_start_attempt = 0;
	}

	errno = 0;
	return _child_set_flag(sd, MASK_DISABLED, !enable);
}

int
supervisor_children_set_delay(const char *key, gboolean enabled)
{
	return supervisor_children_set_flag(key, MASK_DELAYED, enabled);
}

int
supervisor_children_set_respawn(const char *key, gboolean enabled)
{
	return supervisor_children_set_flag(key, MASK_RESPAWN, enabled);
}

int
supervisor_children_repair(const char *key)
{
	return supervisor_children_set_flag(key, MASK_BROKEN, FALSE);
}

int
supervisor_children_status(const char *key, gboolean to_be_started)
{
	return supervisor_children_set_flag(key, MASK_STARTED, to_be_started);
}

int
supervisor_children_restart(const char *key)
{
	/* Remove flag to allow restart if child was broken */
	supervisor_children_set_flag(key, MASK_BROKEN, FALSE);

	return supervisor_children_set_flag(key, MASK_RESTART, TRUE);
}

int
supervisor_children_repair_all(void)
{
	int count = 0;
	struct child_s *sd;

	FOREACH_CHILD(sd) {
		if (FLAG_HAS(sd, MASK_BROKEN)) {
			FLAG_DEL(sd, MASK_BROKEN);
			count ++;
		}
	}

	errno = 0;
	return count;
}

/* ------------------------------------------------------------------------- */

int
supervisor_children_set_limit(const gchar *key, enum supervisor_limit_e what, gint64 value)
{
	struct child_s *sd;

	g_assert_nonnull(key);

	if (what < SUPERV_LIMIT_THREAD_STACK || what > SUPERV_LIMIT_CORE_SIZE) {
		errno = EINVAL;
		return -1;
	}
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	DEBUG("Setting rlimit [%d] to [%"G_GINT64_FORMAT"] for key [%s]", what, value, key);
	errno = 0;
	switch (what) {
		case SUPERV_LIMIT_THREAD_STACK:
			sd->rlimits.stack_size = value;
			return 0;
		case SUPERV_LIMIT_CORE_SIZE:
			sd->rlimits.core_size = value;
			return 0;
		case SUPERV_LIMIT_MAX_FILES:
			sd->rlimits.nb_files = value;
			return 0;
	}

	errno = EINVAL;
	return -1;
}

int
supervisor_children_set_working_directory(const gchar *key, const gchar *dir)
{
	g_assert_nonnull(key);
	g_assert_nonnull(dir);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	if (sd->working_directory)
		g_free(sd->working_directory);
	sd->working_directory = g_strdup(dir);

	errno = 0;
	return 0;
}

int
supervisor_children_setenv(const gchar *key, const gchar *envkey,
	const gchar *envval, gchar separator)
{
	g_assert_nonnull(key);
	g_assert_nonnull(envkey);
	g_assert_nonnull(envval);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	gboolean done = FALSE;
	for (GSList *l=sd->env; l && l->next ;l=l->next->next) {
		GSList *k = l;
		GSList *v = l->next;
		if (!strcmp(envkey, (gchar*) k->data)) {
			if (!separator) {
				TRACE("Replacing [%s] by [%s]", envkey, envval);
				g_free (v->data);
				v->data = g_strdup (envval);
			} else {
				TRACE("Prepending [%s] with [%s]", envkey, envval);
				gchar *old = v->data;
				v->data = g_strdup_printf("%s%c%s", envval, separator, old);
				g_free (old);
			}
			done = TRUE;
			break;
		}
	}
	if (!done) {
		TRACE("Initiating [%s] with [%s]", envkey, envval);
		GSList *kv = g_slist_append(NULL, g_strdup(envkey));
		kv = g_slist_append(kv, g_strdup(envval));
		sd->env = g_slist_concat(sd->env, kv);
	}
	errno = 0;
	return 0;
}

void
supervisor_children_inherit_env(const gchar *key)
{
	gchar **keys = g_listenv();
	if (keys) {
		for (gchar **p = keys; *p ;++p)
			(void) supervisor_children_setenv (key, *p, g_getenv(*p), '\0');
		g_strfreev(keys);
	}
}

static void _free(gpointer p1, gpointer p2) { (void) p2; if (p1) g_free(p1); }

int
supervisor_children_clearenv(const gchar *key)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	if (sd->env) {
		g_slist_foreach(sd->env, _free, NULL);
		g_slist_free(sd->env);
	}
	sd->env = NULL;
	errno = 0;
	return 0;
}

int
supervisor_children_set_user_flags(const gchar *key, guint32 flags)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	sd->user_flags |= flags;
	errno = 0;
	return 0;
}

int
supervisor_children_del_user_flags(const gchar *key, guint32 flags)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	sd->user_flags &= ~(flags);
	errno = 0;
	return 0;
}

int
supervisor_children_set_group(const gchar *key, const gchar *group)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	if (group) {
		g_strlcpy(sd->group, group, sizeof(sd->group));
	} else {
		memset(sd->group, 0, sizeof(sd->group));
	}
	errno = 0;
	return 0;
}

int
supervisor_children_set_ids(const gchar *key, gint32 uid, gint32 gid)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}

	sd->uid = uid;
	sd->gid = gid;
	errno = 0;
	return 0;
}

int
supervisor_children_set_delay_sigkill(const char *key, time_t delay)
{
	g_assert_nonnull(key);

	struct child_s *sd;
	if (!(sd = supervisor_get_child(key))) {
		errno = ENOENT;
		return -1;
	}
	sd->delay_before_KILL = delay;
	return 0;
}

