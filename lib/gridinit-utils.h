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

# define FATAL(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define ALERT(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define CRIT(Format,...)   g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define ERROR(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define WARN(Format,...)   g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_WARN,   Format, ##__VA_ARGS__)
# define NOTICE(Format,...) g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_NOTICE, Format, ##__VA_ARGS__)
# define INFO(Format,...)   g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_INFO,   Format, ##__VA_ARGS__)
# define DEBUG(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_DEBUG,  Format, ##__VA_ARGS__)
# define TRACE(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_TRACE,  Format, ##__VA_ARGS__)

GError* g_error_printf(const char *dom, int code, const char *fmt, ...);

extern time_t supervisor_default_delay_KILL;

/* Children monitoring ----------------------------------------------------- */

enum supervisor_limit_e {
	SUPERV_LIMIT_THREAD_STACK=1,
	SUPERV_LIMIT_MAX_FILES=2,
	SUPERV_LIMIT_CORE_SIZE=3
};

struct child_info_s {
	const char *key;
	const char *cmd;
	gint pid;
	guint uid;
	guint gid;
	gboolean enabled;
	gboolean respawn;
	time_t last_start_attempt;
	guint counter_started;
	guint counter_died;
	struct {
		long core_size;
		long stack_size;
		long nb_files;
	} rlimits;

	/* added at the end for binary backward compatibility */
	gboolean broken;
	gboolean breakable;
	guint32 user_flags;
	const char *group;
	gboolean started;
};

typedef void (supervisor_postfork_f) (void *udata);

typedef void (supervisor_cb_f) (void *udata, struct child_info_s *ci);


void supervisor_children_init(void);

/* Sets an optional function that will be used just after the fork */
void supervisor_set_callback_postfork(supervisor_postfork_f *cb, void *udata);

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

/* Sets the 'enabled' flag on the service */
int supervisor_children_enable(const char *key, gboolean enable);

/* Sets the 'autorespawn' flag on this service */
int supervisor_children_set_respawn(const char *key, gboolean enabled);

/* Marks the service to be started or stopped.  */
int supervisor_children_status(const char *key, gboolean to_be_started);

/* Starts a service that died too often */
int supervisor_children_repair(const char *key);

/* Sets/Disable the "delayed restart" behavior for a process */
int supervisor_children_set_delay(const char *key, gboolean enabled);

/* Calls supervisor_children_repair() on each broken service */
int supervisor_children_repair_all(void);

/* Restart a service */
int supervisor_children_restart(const char *key);

int supervisor_children_set_limit(const gchar *key,
		enum supervisor_limit_e what, gint64 value);

/* Runs the children list and call the callback fnction on each element */
gboolean supervisor_run_services(void *ptr, supervisor_cb_f callback);

int supervisor_children_set_working_directory(const gchar *key,
		const gchar *dir);

int supervisor_children_setenv(const gchar *key, const gchar *envkey,
	const gchar *envval, gchar separator);

void supervisor_children_inherit_env(const gchar *key);

int supervisor_children_clearenv(const gchar *key);

int supervisor_children_set_user_flags(const gchar *key, guint32 flags);

int supervisor_children_del_user_flags(const gchar *key, guint32 flags);

int supervisor_children_set_group(const gchar *key, const gchar *group);

int supervisor_children_get_info(const gchar *key, struct child_info_s *ci);

int supervisor_children_set_ids(const gchar *key, gint32 uid, gint32 gid);

int supervisor_children_set_delay_sigkill(const char *key, time_t delay);

/* Privileges -------------------------------------------------------------- */

gboolean supervisor_rights_init(const char *user_name, const char *group_name,
		GError ** error);

int supervisor_rights_gain(void);

int supervisor_rights_lose(void);

/* Processus limits */

int supervisor_limit_set(enum supervisor_limit_e what, gint64 value);

int supervisor_limit_get(enum supervisor_limit_e what, gint64 *value);

#endif
