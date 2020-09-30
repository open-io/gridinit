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

#ifndef __SUPERV_UTILS_H__
# define __SUPERV_UTILS_H__
# include <glib.h>
# ifndef  SUPERVISOR_LIMIT_CHILDKEYSIZE
#  define SUPERVISOR_LIMIT_CHILDKEYSIZE 128
# endif
# ifndef  SUPERVISOR_LIMIT_GROUPSIZE
#  define SUPERVISOR_LIMIT_GROUPSIZE 256
# endif
# ifndef  SUPERVISOR_DEFAULT_TIMEOUT_KILL
#  define SUPERVISOR_DEFAULT_TIMEOUT_KILL 60
# endif
# include <sys/types.h>
# include <unistd.h>

# define GRID_LOGLVL_TRACE  (32 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_DEBUG  (16 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_INFO   (8  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_NOTICE (4  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_WARN   (2  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_ERROR  (1  << G_LOG_LEVEL_USER_SHIFT)

# define FATAL(Format,...)  g_log(LOG_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define ALERT(Format,...)  g_log(LOG_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define CRIT(Format,...)   g_log(LOG_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define ERROR(Format,...)  g_log(LOG_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define WARN(Format,...)   g_log(LOG_DOMAIN, GRID_LOGLVL_WARN,   Format, ##__VA_ARGS__)
# define NOTICE(Format,...) g_log(LOG_DOMAIN, GRID_LOGLVL_NOTICE, Format, ##__VA_ARGS__)
# define INFO(Format,...)   g_log(LOG_DOMAIN, GRID_LOGLVL_INFO,   Format, ##__VA_ARGS__)
# define DEBUG(Format,...)  g_log(LOG_DOMAIN, GRID_LOGLVL_DEBUG,  Format, ##__VA_ARGS__)
# define TRACE(Format,...)  g_log(LOG_DOMAIN, GRID_LOGLVL_TRACE,  Format, ##__VA_ARGS__)

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
#define FLAG_HAS(sd,M) ((sd)->flags & (M))

#define CHILD_ENABLED(c)   !FLAG_HAS(c,MASK_DISABLED)
#define CHILD_STARTED(c)    FLAG_HAS(c,MASK_STARTED)
#define CHILD_RESPAWN(c)    FLAG_HAS(c,MASK_RESPAWN)
#define CHILD_RESTART(c)    FLAG_HAS(c,MASK_RESTART)
#define CHILD_BROKEN(c)     FLAG_HAS(c,MASK_BROKEN)
#define CHILD_BREAKABLE(c) !FLAG_HAS(c,MASK_NEVER_BROKEN)
#define CHILD_OBSOLETE(c)   FLAG_HAS(c,MASK_OBSOLETE)

#define CHILD_DIED(c)      ((c)->user_flags & USERFLAG_PROCESS_DIED)
#define CHILD_RESTARTED(c) ((c)->user_flags & USERFLAG_PROCESS_RESTARTED)

extern time_t supervisor_default_delay_KILL;

extern GQuark gq_log;

/* Children monitoring ----------------------------------------------------- */

enum supervisor_limit_e {
	SUPERV_LIMIT_THREAD_STACK=1,
	SUPERV_LIMIT_MAX_FILES=2,
	SUPERV_LIMIT_CORE_SIZE=3
};

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


typedef void (supervisor_cb_f) (void *udata, struct child_s *sd);

typedef gboolean (supervisor_run_cb_f) (void *udata, struct child_s *sd);


void supervisor_children_init(void);

void supervisor_children_fini(void);

guint supervisor_children_cleanall(void);

void supervisor_children_stopall(guint max_retries);

guint supervisor_children_killall(int sig);

guint supervisor_children_catharsis(void *udata, supervisor_cb_f cb);

gboolean supervisor_children_register(const gchar *key, const gchar *cmd);

/* Marks the services still obsolete as DISABLED and to be stopped.
   Services still carry the OBSOLETE flag after this step. */
guint supervisor_children_disable_obsolete(void);

/* Mark all the services as obsolete. This is used when reloading a config. */
guint supervisor_children_mark_obsolete(void);

/* Stops the UP services that are in state that does not allow them to run.
   This includes services DOWN, BROKEN, STOPPED, DISABLED.
   Will send SIGKILL until expiration, then SIGTERM. */
guint supervisor_children_kill_disabled(void);

/* starts all the stopped services in a state proper to be restarted */
guint supervisor_children_start_enabled(void *udata, supervisor_cb_f cb);

/* Calls supervisor_children_repair() on each broken service */
int supervisor_children_repair_all(void);

/* Runs the children list and call the callback fnction on each element */
gint supervisor_run_services(void *ptr, supervisor_run_cb_f callback);

struct child_s * supervisor_get_child(const gchar *key);

/* ------------------------------------------------------------------------- */

/* Sets the 'enabled' flag on the service */
int child_enable(struct child_s *child, gboolean enable);

/* Sets the 'autorespawn' flag on this service */
int child_set_respawn(struct child_s *child, gboolean enabled);

/* Marks the service to be started or stopped.  */
int child_status(struct child_s *child, gboolean to_be_started);

/* Starts a service that died too often */
int child_repair(struct child_s *child);

/* Sets/Disable the "delayed restart" behavior for a process */
int child_set_delay(struct child_s *child, gboolean enabled);

/* Restart a service */
int child_restart(struct child_s *child);

void child_set_limit(struct child_s *child,
		enum supervisor_limit_e what, gint64 value);

void child_set_working_directory(struct child_s *child,
		const gchar *dir);

void child_setenv(struct child_s *child, const gchar *envkey,
	const gchar *envval, gchar separator);

void child_inherit_env(struct child_s *child);

void child_clearenv(struct child_s *child);

void child_set_user_flags(struct child_s *child, guint32 flags);

void child_del_user_flags(struct child_s *child, guint32 flags);

void child_set_group(struct child_s *child, const gchar *group);

void child_set_ids(struct child_s *child, gint32 uid, gint32 gid);

void child_set_delay_sigkill(struct child_s *child, time_t delay);

/* Privileges -------------------------------------------------------------- */

gboolean supervisor_rights_init(const char *user_name, const char *group_name,
		GError ** error);

int supervisor_rights_gain(void);

int supervisor_rights_lose(void);

/* Processus limits */

int supervisor_limit_set(enum supervisor_limit_e what, gint64 value);

int supervisor_limit_get(enum supervisor_limit_e what, gint64 *value);

#endif
