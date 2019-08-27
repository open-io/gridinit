/*
gridinit, a monitor for non-daemon processes.
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
#include <stdio.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <syslog.h>
#include <glob.h>

#include <glib.h>
#include <libdill.h>

#include <gridinit-utils.h>
#include "./gridinit_internals.h"

#define USERFLAG_PROCESS_DIED      0x00000002
#define USERFLAG_PROCESS_RESTARTED 0x00000004
#define UNUSED __attribute__ ((unused))

#define BOOL(i) ((i)!=0)

int main_log_level_default = 0x7F;
int main_log_level = 0x7F;
gint64 main_log_level_update = 0;

GQuark gq_log = 0;

static char syslog_id[256] = "";
static char sock_path[1024] = GRIDINIT_SOCK_PATH;
static char pidfile_path[1024] = "";
static char default_working_directory[1024] = "";
static char *config_path = NULL;
static char *config_subdir = NULL;

static char **groups_only_cli = NULL;
static char **groups_only_cfg = NULL;

static volatile gboolean flag_quiet = FALSE;
static volatile gboolean flag_daemon = FALSE;
static volatile gboolean flag_running = TRUE;
static volatile gboolean flag_check_socket = FALSE;
static volatile gboolean flag_more_verbose = FALSE;
static volatile gboolean flag_version = FALSE;

static volatile gint32 default_uid = -1;
static volatile gint32 default_gid = -1;

static volatile gboolean inherit_env = 0;

static GHashTable *default_env = NULL;

static gboolean _cfg_reload(gboolean services_only, GError **err);

static GOptionEntry entries[] = {
	{"daemonize", 'd', 0, G_OPTION_ARG_NONE, (gboolean *)&flag_daemon,
	 "Detaches then daemonizes the gridinit", NULL},
	{"group", 'g', 0, G_OPTION_ARG_STRING_ARRAY, &groups_only_cli,
	 "limits the services loading to those belonging to the specified"
	 "group. This option can be repeated", "GROUP"},
	{"quiet", 'q', 0, G_OPTION_ARG_NONE, (gboolean *)&flag_quiet,
	 "quiet mode, suppress non-error output",NULL},
	{"version", 'V', 0, G_OPTION_ARG_NONE, (gboolean *)&flag_version,
	 "Display the version of gridinit", NULL},
	{"verbose", 'v', 0, G_OPTION_ARG_NONE, (gboolean *)&flag_more_verbose,
	 "verbose output mode", NULL},
	{"syslog", 's', 0, G_OPTION_ARG_STRING, &syslog_id,
	 "enable logs using syslog with the given ID", "ID"},
	{NULL}
};

/* ------------------------------------------------------------------------- */

static void
logger_verbose(void)
{
	main_log_level = (main_log_level * 2) + 1;
	main_log_level_update = g_get_monotonic_time();
}

static void
logger_verbose_default(void)
{
	main_log_level_default = (main_log_level_default * 2) + 1;
	main_log_level = main_log_level_default;
}

static void
logger_init_level(int l)
{
	main_log_level_default = main_log_level = (l?(l|0x7F):0);
}

#define REAL_LEVEL(L)   (guint32)((L) >> G_LOG_LEVEL_USER_SHIFT)
#define ALLOWED_LEVEL() REAL_LEVEL(main_log_level)

static gboolean
glvl_allowed(register GLogLevelFlags lvl)
{
	return !flag_quiet && ((lvl & 0x7F)
		|| (ALLOWED_LEVEL() >= REAL_LEVEL(lvl)));
}

static void
_str_set_array(gboolean concat, gchar ***dst, gchar *str)
{
	gchar **tokens, **t;

	if (!concat && *dst != NULL) {
		g_strfreev(*dst);
		*dst = NULL;
	}

	if (!(tokens = g_strsplit(str, ",", 0))) {
		FATAL("split error");
		abort();
		return;
	}

	if (!*dst)
		*dst = g_malloc0(2 * sizeof(gchar *));

	for (t=tokens; *t ;t++) {
		gchar **new_array = NULL;
		size_t len;

		len = g_strv_length(*dst);
		new_array = g_realloc(*dst, sizeof(gchar *) * (len+2));
		new_array[len] = g_strdup(*t);
		new_array[len+1] = NULL;
		*dst = new_array;
		TRACE("Managing group [%s]", new_array[len]);
	}

	g_strfreev(tokens);
}


/* Process management helpers ---------------------------------------------- */

static void
alert_proc_died(void *udata, struct child_info_s *ci)
{
	(void) udata;

	if (ci->started)
		supervisor_children_set_user_flags(ci->key, USERFLAG_PROCESS_DIED);
}

static void
alert_send_deferred(void *udata, struct child_info_s *ci)
{
	(void) udata;

	/* Handle the alerting of broken services */
	if ((ci->user_flags & USERFLAG_PROCESS_DIED) && ci->broken) {
		supervisor_children_del_user_flags(ci->key, USERFLAG_PROCESS_DIED);
		ERROR("Process broken [%s] %s", ci->key, ci->cmd);
	}

	/* Handle the alerting of successfully restarted services */
	if (!(ci->user_flags & USERFLAG_PROCESS_DIED) && (ci->user_flags & USERFLAG_PROCESS_RESTARTED)) {
		supervisor_children_del_user_flags(ci->key, USERFLAG_PROCESS_RESTARTED);
		NOTICE("Process restarted [%s] %s", ci->key, ci->cmd);
	}
}

static void
alert_proc_started(void *udata, struct child_info_s *ci)
{
	(void) udata;

	/* Note service has restarted */
	if (ci->user_flags & USERFLAG_PROCESS_DIED) {
		supervisor_children_del_user_flags(ci->key, USERFLAG_PROCESS_DIED);
		supervisor_children_set_user_flags(ci->key, USERFLAG_PROCESS_RESTARTED);
	}
}

static void
thread_ignore_signals(void)
{
	sigset_t new_set, old_set;

	sigemptyset(&new_set);
	sigemptyset(&old_set);
	sigaddset(&new_set, SIGQUIT);
	sigaddset(&new_set, SIGINT);
	sigaddset(&new_set, SIGALRM);
	sigaddset(&new_set, SIGHUP);
	sigaddset(&new_set, SIGCONT);
	sigaddset(&new_set, SIGUSR1);
	sigaddset(&new_set, SIGUSR2);
	sigaddset(&new_set, SIGTERM);
	sigaddset(&new_set, SIGPIPE);
	sigaddset(&new_set, SIGCHLD);
	if (0 > sigprocmask(SIG_BLOCK, &new_set, &old_set))
		ALERT("Some signals could not be blocked : %s", strerror(errno));
}

/* COMMANDS management ----------------------------------------------------- */


static void
service_run_groupv(int nb_groups, char **groupv, GString *out, supervisor_cb_f cb)
{
	guint count;

	void group_filter(void *u1, struct child_info_s *ci) {
		const char *group = u1;
		if (group && !gridinit_group_in_set(group, ci->group)) {
			TRACE("start: Skipping [%s] with group [%s]", ci->key, ci->group);
		} else {
			TRACE("Calback on service [%s]", ci->key);
			cb(out, ci);
			++ count;
		}
	}

	if (!nb_groups || !groupv) {
		supervisor_run_services(NULL, group_filter);
	} else {
		for (int i=0; i<nb_groups ;i++) {
			char *what = groupv[i];
			if (*what == '@') {
				TRACE("Callback on group [%s]", what);
				count = 0;
				supervisor_run_services(what+1, group_filter);
				if (!count && out) {
					/* notifies the client the group has not been found */
					g_string_append_printf(out, "%d %s\n", ENOENT, what);
				}
			}
			else {
				struct child_info_s ci = {};
				if (0 == supervisor_children_get_info(what, &ci)) {
					TRACE("Calback on service [%s]", what);
					cb(out, &ci);
				} else {
					if (out)
						g_string_append_printf(out, "%d %s\n", errno, what);
					if (errno == ENOENT)
						TRACE("Service not found [%s]\n", what);
					else
						ERROR("Internal error [%s]: %s", what, strerror(errno));
				}
			}
		}
	}
}

static void
command_start(GString *out, int argc, char **argv)
{
	void start_process(void *u UNUSED, struct child_info_s *ci) {
		supervisor_children_repair(ci->key);

		switch (supervisor_children_status(ci->key, TRUE)) {
		case 0:
			INFO("Already started [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", EALREADY, ci->key);
			return;
		case 1:
			INFO("Started [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", 0, ci->key);
			return;
		default:
			WARN("Cannot start [%s]: %s", ci->key, strerror(errno));
			g_string_append_printf(out, "%d %s\n", errno, ci->key);
			return;
		}
	}

	g_assert_nonnull(out);
	return service_run_groupv(argc, argv, out, start_process);
}

static void
command_stop(GString *out, int argc, char **argv)
{
	void stop_process(void *u UNUSED, struct child_info_s *ci) {
		switch (supervisor_children_status(ci->key, FALSE)) {
		case 0:
			INFO("Already stopped [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", EALREADY, ci->key);
			return;
		case 1:
			INFO("Stopped [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", 0, ci->key);
			return;
		default:
			WARN("Cannot stop [%s]: %s", ci->key, strerror(errno));
			g_string_append_printf(out, "%d %s\n", errno, ci->key);
			return;
		}
	}

	g_assert_nonnull(out);
	return service_run_groupv(argc, argv, out, stop_process);
}

static void
command_restart(GString *out, int argc, char **argv)
{
	void restart_process(void *u UNUSED, struct child_info_s *ci) {
		switch (supervisor_children_restart(ci->key)) {
		case 0:
			INFO("Already restarted [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", EALREADY, ci->key);
			return;
		case 1:
			INFO("Restart [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", 0, ci->key);
			return;
		default:
			WARN("Cannot restart [%s]: %s", ci->key, strerror(errno));
			g_string_append_printf(out, "%d %s\n", errno, ci->key);
			return;
		}
	}

	g_assert_nonnull(out);
	return service_run_groupv(argc, argv, out, restart_process);
}

static void
command_show(GString *out, int argc UNUSED, char **argv UNUSED)
{
	void print_process(void *u UNUSED, struct child_info_s *ci) {
		g_string_append_printf(out,
				"%d "
				"%d %d %d "
				"%u %u "
				"%ld "
				"%ld %ld %ld "
				"%u %u "
				"%s %s %s\n",
			ci->pid,
			BOOL(ci->enabled), BOOL(ci->broken), BOOL(ci->respawn),
			ci->counter_started, ci->counter_died,
			ci->last_start_attempt,
			ci->rlimits.core_size, ci->rlimits.stack_size, ci->rlimits.nb_files,
			ci->uid, ci->gid,
			ci->key, ci->group, ci->cmd);
	}

	g_assert_nonnull(out);
	return service_run_groupv(0, NULL, out, print_process);
}

static void
command_repair(GString *out, int argc, char **argv)
{
	void repair_process(void *u UNUSED, struct child_info_s *ci) {
		if (0 == supervisor_children_repair(ci->key)) {
			INFO("Repaired [%s]", ci->key);
			g_string_append_printf(out, "%d %s\n", 0, ci->key);
		} else {
			WARN("Failed to repair [%s]: %s", ci->key, strerror(errno));
			g_string_append_printf(out, "%d %s\n", errno, ci->key);
		}
	}

	g_assert_nonnull(out);
	return service_run_groupv(argc, argv, out, repair_process);
}

static void
command_reload(GString *out, int argc UNUSED, char **argv UNUSED)
{
	GError *err = NULL;

	g_assert_nonnull(out);

	guint count = supervisor_children_mark_obsolete();
	g_string_append_printf(out, "%d obsoleted %u processes\n", 0, count);
	TRACE("Marked %u obsolete services\n", count);

	if (!_cfg_reload(TRUE, &err)) {
		WARN("error: Failed to reload the configuration from [%s]: (%d) %s\n",
				config_path, err ? err->code : 0, err ? err->message : "?");
		g_string_append_printf(out, "%d reload\n", err ? err->code : EINVAL);
	} else {
		g_string_append(out, "0 reload\n");
		count = supervisor_children_disable_obsolete();
		g_string_append_printf(out, "0 disabled %u obsolete processes\n", count);

		if (count)
			NOTICE("Services refreshed, %u disabled\n", count);
		else
			TRACE("Services refreshed, %u disabled\n", count);
	}
}

typedef void (*cmd_f) (GString *out, int argc, char **argv);

static cmd_f
__resolve_command(const gchar *n)
{
	static struct cmd_mapping_s {
		const gchar *cmd_name;
		cmd_f cmd_callback;
	} COMMANDS [] = {
		{"status",  command_show },
		{"repair",  command_repair },
		{"start",   command_start },
		{"stop",    command_stop },
		{"restart", command_restart },
		{"reload",  command_reload },
		{NULL,      NULL}
	};

	for (struct cmd_mapping_s *cmd = COMMANDS; cmd->cmd_name ;cmd++) {
		if (0 == g_ascii_strcasecmp(n, cmd->cmd_name))
			return cmd->cmd_callback;
	}
	return NULL;
}

static GString *
_command_execute(const char *cmd)
{
	int argc = 0;
	gchar **argv = NULL;
	GString *out = g_string_sized_new(2048);

	if (!g_shell_parse_argv(cmd, &argc, &argv, NULL)) {
		g_string_append(out, "1 malformed request\n");
	} else {
		cmd_f callback = __resolve_command(argv[0]);
		if (NULL != callback)
			(callback)(out, argc-1, argv+1);
		else
			g_string_append(out, "1 unexpected request\n");
	}

	if (argv) g_strfreev(argv);
	return out;
}


/* Server socket pool management ------------------------------------------- */

static GString *
_read_line(int ldh, const int64_t dl)
{
	GString *out = g_string_new("");
	gchar c;
	int r;

label_retry:
	c = '\0';
	r = dill_brecv(ldh, &c, 1, dl);
	if (r < 0) {
		g_string_free(out, TRUE);
		return NULL;
	}
	if (c != '\n') {
		g_string_append_c(out, c);
		goto label_retry;
	}
	return out;
}

static dill_coroutine void
_client_run(int ch, int ldh_client)
{
	TRACE("client dill_now running h=%d", ldh_client);
	GString *in = _read_line(ldh_client, dill_now() + 5000);
	if (!in) {
		WARN("Client failed: (%d) %s", errno, strerror(errno));
	} else {
		TRACE("Client h=%d recv=%" G_GSIZE_FORMAT " [%s]", ldh_client, in ? in->len : 0, in ? in->str : NULL);
		GString *out = _command_execute(in->str);
		while (out->len > 0 && out->str[out->len-1] == '\n')
			g_string_truncate(out, out->len - 1);
		dill_bsend(ldh_client, out->str, out->len, dill_now() + 5000);
		g_string_free(in, TRUE);
		g_string_free(out, TRUE);
	}

	TRACE("client dill_now exiting h=%d", ldh_client);
	int rc = dill_hclose(ldh_client);
	g_assert(rc == 0);

	int v = 0;
	(void) dill_chsend(ch, &v, sizeof(v), 0);
}

static dill_coroutine void
_server_run(int ch, const char *path)
{
	struct dill_bundle_storage bundle_storage = {};
	int workers = dill_bundle_mem(&bundle_storage);
	g_assert(workers >= 0);

	int ldh_server = dill_ipc_listen(path, 1024);
	if (ldh_server < 0) {
		ERROR("Failed to listen to the commands socket: (%d) %s", errno, strerror(errno));
		flag_running = 0;
		return;
	}

	DEBUG("Initiated a server socket on [%s] h=%d", sock_path, ldh_server);

	while (flag_running) {
		int ldh_client = dill_ipc_accept(ldh_server, dill_now() + 1000);
		if (ldh_client >= 0) {
			TRACE("Client accepted h=%d", ldh_client);
			dill_bundle_go(workers, _client_run(ch, ldh_client));
		} else if (errno != EAGAIN && errno != EINTR && errno != ETIMEDOUT) {
			WARN("accept error: (%d) %s", errno, strerror(errno));
			flag_running = 0;
		}
	}

	int rc = dill_hclose(ldh_server);
	g_assert(rc == 0);

	dill_bundle_wait(workers, -1);
	dill_hclose(workers);

	unlink(path);
}

static void
_single_check(void)
{
	guint proc_count = supervisor_children_catharsis(NULL, alert_proc_died);
	if (proc_count > 0)
		DEBUG("%u services died", proc_count);

	/* alert for the services that died */
	supervisor_run_services(NULL, alert_send_deferred);

	proc_count = supervisor_children_kill_disabled();
	if (proc_count)
		DEBUG("Killed %u disabled/stopped services", proc_count);

	proc_count = supervisor_children_start_enabled(NULL, alert_proc_started);
	if (proc_count)
		DEBUG("Started %u enabled services", proc_count);

	if (flag_more_verbose) {
		NOTICE("Increasing verbosity for 15 minutes");
		logger_verbose();
		flag_more_verbose = 0;
	}

	if (main_log_level_update) {
		gint64 when = g_get_monotonic_time() - (15 * G_TIME_SPAN_MINUTE);
		if (main_log_level_update < when) {
			NOTICE("Verbosity reset to its default value");
			main_log_level = main_log_level_default;
			main_log_level_update = 0;
		}
	}
}

static void
_routine_check(int ch)
{
	int v = 0;
	while (flag_running) {
		_single_check();
		/* wake-up periodically or upon a ping from a cliet worker */
		int rc = dill_chrecv(ch, &v, sizeof(v), dill_now() + 1000);
		if (rc < 0 && errno != ETIMEDOUT)
			return;
	}
}


/* Configuration ----------------------------------------------------------- */

static gboolean
_cfg_value_is_true(const gchar *val)
{
	return val && (
		   0==g_ascii_strcasecmp(val,"true")
		|| 0==g_ascii_strcasecmp(val,"yes")
		|| 0==g_ascii_strcasecmp(val,"enable")
		|| 0==g_ascii_strcasecmp(val,"enabled")
		|| 0==g_ascii_strcasecmp(val,"on"));
}

static GHashTable *
_make_empty_env (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static GHashTable*
_cfg_extract_parameters (GKeyFile *kf, const char *s, const char *p, GError **err)
{
	gsize size=0;
	gchar **all_keys = g_key_file_get_keys (kf, s, &size, err);
	if (!all_keys)
		return NULL;

	GHashTable *ht = _make_empty_env ();
	for (gchar **pk = all_keys; all_keys && *pk ;pk++) {
		const char *key = *pk;
		if (g_str_has_prefix(key, p)) {
			gchar *value = g_key_file_get_value (kf, s, key, err);
			g_hash_table_insert (ht, g_strdup(key + strlen(p)), value);
		}
	}

	g_strfreev(all_keys);
	return ht;
}

static gchar*
__get_and_enlist(GSList **gc, GKeyFile *kf, const gchar *section, const gchar *key)
{
	gchar *str;

	if (NULL != (str = g_key_file_get_string(kf, section, key, NULL)))
		*gc = g_slist_prepend(*gc, str);

	return str;
}

static void
my_free1(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		g_free(p1);
}

static gboolean
_str_is_num(const gchar *s)
{
	for (; *s ; s++) {
		if (!g_ascii_isdigit(*s))
			return FALSE;
	}
	return TRUE;
}

/** XXX JFS Linux-specific code */
static gboolean
uid_exists(const gchar *str, gint32 *id)
{
	struct passwd pwd, *p_pwd;
	gchar buf[1024];

	if (_str_is_num(str)) {
		gint64 i64;

		i64 = g_ascii_strtoll(str, NULL, 10);
		*id = i64;
		return TRUE;
	}

	if (0 != getpwnam_r(str, &pwd, buf, sizeof(buf), &p_pwd))
		return FALSE;

	*id = pwd.pw_uid;
	return TRUE;
}

/** XXX JFS Linux-specific code */
static gboolean
gid_exists(const gchar *str, gint32 *id)
{
	struct group grp, *p_grp;
	gchar buf[1024];

	if (_str_is_num(str)) {
		gint64 i64;

		i64 = g_ascii_strtoll(str, NULL, 10);
		*id = i64;
		return TRUE;
	}

	if (0 != getgrnam_r(str, &grp, buf, sizeof(buf), &p_grp))
		return FALSE;

	*id = grp.gr_gid;
	return TRUE;
}

static void
_cfg_service_load_env(GKeyFile *kf, const gchar *section, const gchar *str_key)
{
	GHashTable *ht_env = _cfg_extract_parameters(kf, section, "env.", NULL);
	if (!ht_env || !g_hash_table_size(ht_env)) {
		TRACE("No env found for [%s]", section);
		if (ht_env)
			g_hash_table_destroy (ht_env);
		return ;
	}

	g_assert (ht_env != NULL && g_hash_table_size (ht_env) > 0);

	GHashTableIter iter_env;
	gchar *k, *v;
	g_hash_table_iter_init(&iter_env, ht_env);
	while (g_hash_table_iter_next(&iter_env, (gpointer*)&k, (gpointer*)&v)) {
		if (0 != supervisor_children_setenv(str_key, k, v, inherit_env ? ':' : '\0'))
			WARN("[%s] saved environment [%s]=[%s] : %s",
				str_key, (gchar*)k, (gchar*)v, strerror(errno));
		else
			DEBUG("[%s] saved environment variable [%s]=[%s]",
					str_key, (gchar*)k, (gchar*)v);
	}

	DEBUG("[%s] environment saved", str_key);
	g_hash_table_destroy(ht_env);
}

static gboolean
_group_is_accepted(gchar *str_key, gchar *str_group)
{
	if (!groups_only_cli && !groups_only_cfg) {
		TRACE("Service [%s] accepted : gridinit not restricted to some groups", str_key);
		return TRUE;
	}
	if (!str_group) {
		DEBUG("Service [%s] ignored : no group provided", str_key);
		return FALSE;
	}

	gchar **which = groups_only_cli ? groups_only_cli : groups_only_cfg;
	for (gchar **p_group=which; *p_group ;p_group++) {
		if (0 == g_ascii_strcasecmp(*p_group, str_group)) {
			TRACE("Service [%s] accepted : belongs to an allowed group", str_key);
			return TRUE;
		}
	}

	DEBUG("Service [%s] ignored : group not managed", str_key);
	return FALSE;
}

static gboolean
_service_exists(const gchar *key)
{
	struct child_info_s ci = {};
	return 0 == supervisor_children_get_info(key, &ci);
}

static gboolean
_cfg_section_service(GKeyFile *kf, const gchar *section, GError **err)
{
	GSList *gc = NULL;
	gboolean rc = FALSE, already_exists;
	gchar *str_key;
	gchar *str_command, *str_enabled, *str_startatboot, *str_ondie,
		*str_uid, *str_gid,
		*str_limit_stack, *str_limit_core, *str_limit_fd,
		*str_wd, *str_group, *str_delay_sigkill;
	gint32 uid, gid;

	uid = gid = -1;
	str_key = strchr(section, '.') + 1;
	str_delay_sigkill = __get_and_enlist(&gc, kf, section, CFG_KEY_DELAY_KILL);
	str_command = __get_and_enlist(&gc, kf, section, "command");
	str_enabled = __get_and_enlist(&gc, kf, section, "enabled");
	str_ondie = __get_and_enlist(&gc, kf, section, "on_die");
	str_startatboot = __get_and_enlist(&gc, kf, section, "start_at_boot");
	str_uid = __get_and_enlist(&gc, kf, section, CFG_KEY_UID);
	str_gid = __get_and_enlist(&gc, kf, section, CFG_KEY_GID);
	str_group = __get_and_enlist(&gc, kf, section, CFG_KEY_GROUP);
	str_limit_fd = __get_and_enlist(&gc, kf, section, CFG_KEY_LIMIT_NBFILES);
	str_limit_core = __get_and_enlist(&gc, kf, section, CFG_KEY_LIMIT_CORESIZE);
	str_limit_stack = __get_and_enlist(&gc, kf, section, CFG_KEY_LIMIT_STACKSIZE);
	str_wd = __get_and_enlist(&gc, kf, section, CFG_KEY_PATH_WORKINGDIR);

	/* Perform some sanity checks on the given values, to avoid registering
	 * partially setup services */
	if (!_group_is_accepted(str_key, str_group)) {
		rc = TRUE;
		goto label_exit;
	}
	if (str_uid && str_gid && *str_uid && *str_uid) {

		if (!uid_exists(str_uid, &uid)) {
			/* Invalid user */
			*err = g_error_new(gq_log, EINVAL, "Service [%s] cannot cannot receive UID [%s] : errno=%d %s",
		                        str_key, str_uid, errno, strerror(errno));
			goto label_exit;
		}
		if (!gid_exists(str_gid, &gid)) {
			/* Invalid group */
			*err = g_error_new(gq_log, EINVAL, "Service [%s] cannot cannot receive GID [%s] : errno=%d %s",
		                        str_key, str_gid, errno, strerror(errno));
			goto label_exit;
		}
	}

	/* Stat the service and check it is already running.
	 * This is used to avoid changing the started/stopped status
	 * of an existing service, i.e. when its configuration is
	 * being reloaded. */
	already_exists = _service_exists(str_key);

	if (!supervisor_children_register(str_key, str_command))
		goto label_exit;

	/* Enables or not. This is a lock controlled by the configuration
	 * that overrides all other child states. */
	if (0 > supervisor_children_enable(str_key, _cfg_value_is_true(str_enabled))) {
		*err = g_error_new(gq_log, errno, "Service [%s] cannot be marked [%s] : %s",
		                        str_key, (_cfg_value_is_true(str_enabled)?"ENABLED":"DISABLED"),
					strerror(errno));
		goto label_exit;
	}

	if (*default_working_directory) {
		if (0 > supervisor_children_set_working_directory(str_key, default_working_directory))
			WARN("Failed to save default working directory for [%s] : %s", str_key, strerror(errno));
	}

	/* If the service is discovered for the first time, then when
	 * are allowed to change its 'tobe{started,stopped}' status */
	if (!already_exists && str_startatboot) {
		if (0 > supervisor_children_status(str_key, _cfg_value_is_true(str_startatboot)))
			WARN("Failed to set 'tobestarted/tobestopped' for [%s] : %s", str_key, strerror(errno));
	}

	/* on_die management. Respawn, cry */
	if (str_ondie) {
		if (0 == g_ascii_strcasecmp(str_ondie, "cry")) {
			if (0 > supervisor_children_set_respawn(str_key, FALSE))
				WARN("Failed to make [%s] respawn : %s", str_key, strerror(errno));
		}
		else if (0 == g_ascii_strcasecmp(str_ondie, "respawn"))
			supervisor_children_set_respawn(str_key, TRUE);
		else {
			WARN("Service [%s] has an unexpected [%s] value (%s), set to 'respawn'",
				str_key, "on_die", str_ondie);
			supervisor_children_set_respawn(str_key, TRUE);
		}
	}

	/* By default set the current uid/gid, then overwrite this by
	 * possibly configured default uid/gid  */
	supervisor_children_set_ids(str_key, getuid(), getgid());
	if (default_uid>0 && default_gid>0) {
		if (0 > supervisor_children_set_ids(str_key, default_uid, default_gid))
			WARN("Failed to set UID/GID to %d/%d for [%s] : %s",
					default_uid, default_gid, str_key, strerror(errno));
	}

	/* explicit user/group pair */
	if (uid >= 0 && gid >= 0) {
		if (0 > supervisor_children_set_ids(str_key, uid, gid))
			WARN("Failed to set specific UID/GID to %"G_GINT32_FORMAT"/%"G_GINT32_FORMAT" for [%s] : %s",
				uid, gid, str_key, strerror(errno));
	}

	/* alternative limits */
	if (str_limit_stack) {
		gint64 i64 = g_ascii_strtoll(str_limit_stack, NULL, 10);
		supervisor_children_set_limit(str_key, SUPERV_LIMIT_THREAD_STACK, i64 * 1024LL);
	}
	if (str_limit_fd) {
		gint64 i64 = g_ascii_strtoll(str_limit_fd, NULL, 10);
		supervisor_children_set_limit(str_key, SUPERV_LIMIT_MAX_FILES, i64);
	}
	if (str_limit_core) {
		gint64 i64 = g_ascii_strtoll(str_limit_core, NULL, 10);
		supervisor_children_set_limit(str_key, SUPERV_LIMIT_CORE_SIZE, i64 * 1024LL * 1024LL);
	}

	/* Explicit working directory */
	if (str_wd) {
		if (!g_file_test(str_wd, G_FILE_TEST_IS_DIR|G_FILE_TEST_IS_EXECUTABLE))
			WARN("Explicit working directory for [%s] does not exist yet [%s]",
				str_key, str_wd);
		if (0 > supervisor_children_set_working_directory(str_key, str_wd))
			WARN("Failed to set an explicit working directory for [%s] : %s",
				str_key, strerror(errno));
	}

	/* Loads the environment */
	supervisor_children_clearenv(str_key);
	if (inherit_env)
		supervisor_children_inherit_env (str_key);

	_cfg_service_load_env(kf, "Default", str_key);
	_cfg_service_load_env(kf, section, str_key);

	/* reset/set the process's group */
	supervisor_children_set_group(str_key, NULL);
	if (str_group)
		supervisor_children_set_group(str_key, str_group);

	if (str_delay_sigkill) {
		time_t delay = g_ascii_strtoll(str_delay_sigkill, NULL, 10);
		supervisor_children_set_delay_sigkill(str_key, delay);
	}

	rc = TRUE;

label_exit:
	if (gc) {
		g_slist_foreach(gc, my_free1, NULL);
		g_slist_free(gc);
	}
	return rc;
}

static gboolean
_cfg_section_default(GKeyFile *kf, const gchar *section, GError **err)
{
	gchar buf_user[256]="", buf_group[256]="";
	gchar buf_uid[256]="", buf_gid[256]="";
	gchar buf_includes[1024]="";
	gint64 limit_thread_stack = 1024LL * 1024LL;
	gint64 limit_core_size = -1LL;
	gint64 limit_nb_files = 8192LL * 1024LL * 1024LL;
	gint64 delay_sigkill = -1LL;
	gchar **p_key, **keys;

	keys = g_key_file_get_keys(kf, section, NULL, err);
	if (!keys)
		return FALSE;

	/* Load the system limit and the pidfile path */
	for (p_key=keys; *p_key ;p_key++) {
		gchar *str;

		str = g_key_file_get_string(kf, section, *p_key, NULL);

		if (!g_ascii_strcasecmp(*p_key, CFG_KEY_DELAY_KILL)) {
			delay_sigkill = g_ascii_strtoll(str, NULL, 10);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_INHERIT)) {
			inherit_env = g_ascii_strtoll(str, NULL, 10);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_CORESIZE)) {
			limit_core_size = g_ascii_strtoll(str, NULL, 10) * 1024LL * 1024LL;
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_NBFILES)) {
			limit_nb_files = g_ascii_strtoll(str, NULL, 10);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_STACKSIZE)) {
			limit_thread_stack = g_ascii_strtoll(str, NULL, 10) * 1024LL;
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_PATH_WORKINGDIR)) {
			if (!g_file_test(*p_key, G_FILE_TEST_IS_DIR|G_FILE_TEST_IS_EXECUTABLE))
				WARN("Default working directory does not exist yet [%s]", *p_key);
			g_strlcpy(default_working_directory, str, sizeof(default_working_directory));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_PATH_PIDFILE)) {
			g_strlcpy(pidfile_path, str, sizeof(pidfile_path));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LISTEN)) {
			if (str[0] == '/') {
				g_strlcpy(sock_path, str, sizeof(sock_path));
			} else {
				g_printerr("section=%s, key=listen : not a UNIX path, ignored! [%s]\n",
					section, str);
			}
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_USER)) {
			g_strlcpy(buf_user, str, sizeof(buf_user));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_GROUP)) {
			g_strlcpy(buf_group, str, sizeof(buf_group));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_UID)) {
			g_strlcpy(buf_uid, str, sizeof(buf_uid));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_GID)) {
			g_strlcpy(buf_gid, str, sizeof(buf_gid));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_INCLUDES)) {
			g_strlcpy(buf_includes, str, sizeof(buf_includes));
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_GROUPSONLY)) {
			_str_set_array(FALSE, &groups_only_cfg, str);
		}

		g_free(str);
	}
	g_strfreev(keys);

	/* Extract the default environment */
	default_env = _cfg_extract_parameters(kf, section, "env.", NULL);
	if (!default_env)
		default_env = _make_empty_env ();

	/* Set the defautl limits for the services (apply them directly to the gridinit itself) */
	int rc0 = supervisor_limit_set(SUPERV_LIMIT_CORE_SIZE, limit_core_size);
	int rc1 = supervisor_limit_set(SUPERV_LIMIT_MAX_FILES, limit_nb_files);
	int rc2 = supervisor_limit_set(SUPERV_LIMIT_THREAD_STACK, limit_thread_stack);
	DEBUG("Set gridinit limits to [%"G_GINT64_FORMAT", %"G_GINT64_FORMAT", %"G_GINT64_FORMAT"] (%d,%d,%d)",
			limit_core_size, limit_nb_files, limit_thread_stack, rc0, rc1, rc2);

	/* Loads the default UID/GID for the services*/
	if ((*buf_user || *buf_uid) && (*buf_group || *buf_gid)) {
		gchar *ptr_uid, *ptr_gid;
		gint32 uid, gid;

		ptr_gid = *buf_gid ? buf_gid : buf_group;
		ptr_uid = *buf_uid ? buf_uid : buf_user;

		uid = gid = -1;
		if (!uid_exists(ptr_uid, &uid)) {
			WARN("Invalid default UID [%s] : errno=%d %s", ptr_uid, errno, strerror(errno));
			uid = -1;
		}
		if (!gid_exists(ptr_gid, &gid)) {
			WARN("Invalid default GID [%s] : errno=%d %s", ptr_gid, errno, strerror(errno));
			gid = -1;
		}
		if (uid>0 && gid>0) {
			default_uid = uid;
			default_gid = gid;
			NOTICE("Default UID/GID set to %"G_GINT32_FORMAT"/%"G_GINT32_FORMAT, default_uid, default_gid);
		}
	}

	/* Loads the service files */
	if (*buf_includes) {
		if (config_subdir)
			g_free(config_subdir);
		config_subdir = g_strndup(buf_includes, sizeof(buf_includes));
	}

	if (delay_sigkill >= 0) {
		supervisor_default_delay_KILL = delay_sigkill;
	}

	return TRUE;
}

static gboolean
_cfg_reload_file(GKeyFile *kf, gboolean services_only, GError **err)
{
	gboolean rc = FALSE;
	gchar **groups = g_key_file_get_groups(kf, NULL);

	if (!groups) {
		*err = g_error_new(gq_log, EINVAL, "no group");
		return FALSE;
	}

	for (gchar **p_group=groups; *p_group ;p_group++) {

		TRACE("Reading section [%s]", *p_group);

		if (g_str_has_prefix(*p_group, "service.")
				 || g_str_has_prefix(*p_group, "Service.")) {
			INFO("reconfigure : managing service section [%s]", *p_group);
			if (!_cfg_section_service(kf, *p_group, err)) {
				WARN("invalid service section");
				goto label_exit;
			}
		}
		else if (!services_only && !g_ascii_strcasecmp(*p_group, "default")) {
			INFO("reconfigure : loading main parameters from section [%s]", *p_group);
			if (!_cfg_section_default(kf, *p_group, err)) {
				WARN("invalid default section");
				goto label_exit;
			}
		}
		else {
			INFO("reconfigure : ignoring section [%s]", *p_group);
		}
	}
	rc = TRUE;

label_exit:
	g_strfreev(groups);
	return rc;
}

#define SETERRNO(ERR) do { if ((ERR) && *(ERR) && !(*(ERR))->code) (*(ERR))->code = errno; } while (0)
static gboolean
_cfg_reload(gboolean services_only, GError **err)
{
	gboolean rc = FALSE;
	GKeyFile *kf = g_key_file_new();

	if (!g_key_file_load_from_file(kf, config_path, 0, err)) {
		SETERRNO(err);
		WARN("Conf not parseable from [%s]", config_path);
		goto label_exit;
	}

	/* First load the main files */
	if (!_cfg_reload_file(kf, services_only, err)) {
		SETERRNO(err);
		WARN("Conf not loadable from [%s]", config_path);
		goto label_exit;
	}

	/* Then load "globbed" sub files, but only services */
	if (config_subdir) {
		int notify_error(const char *path, int en) {
			NOTICE("errno=%d %s : %s", en, path, strerror(en));
			return 0;
		}
		glob_t subfiles_glob = {};

		DEBUG("Loading services files matching [%s]", config_subdir);

		int glob_rc = glob(config_subdir,
				GLOB_BRACE|GLOB_NOSORT|GLOB_MARK,
				notify_error, &subfiles_glob);
		if (glob_rc != 0) {
			if (glob_rc == GLOB_NOMATCH)
				NOTICE("Service file pattern matched no file!");
			else
				WARN("reconfigure : glob error : %s", strerror(errno));
		}
		else {
			for (char **ps=subfiles_glob.gl_pathv; subfiles_glob.gl_pathv && *ps ;ps++) {
				const char *path = *ps;
				GError *gerr_local = NULL;
				GKeyFile *sub_kf = g_key_file_new();
				if (!g_key_file_load_from_file(sub_kf, path, 0, &gerr_local))
					WARN("Configuration file [%s] not parsed : %s", path,
						gerr_local ? gerr_local->message : "");
				else if (!_cfg_reload_file(sub_kf, TRUE, &gerr_local))
					WARN("Configuration file [%s] not loaded : %s", path,
						gerr_local ? gerr_local->message : "");
				else
					INFO("Loaded service file [%s]", path);

				if (gerr_local)
					g_clear_error(&gerr_local);
				g_key_file_free(sub_kf);
			}
			globfree(&subfiles_glob);
		}
	}

	rc = TRUE;
	INFO("Configuration loaded from [%s]", config_path);

label_exit:
	if (kf)
		g_key_file_free(kf);
	return rc;
}

/* ------------------------------------------------------------------------- */

static guint16
compute_thread_id(GThread *thread)
{
	union { void *p; guint16 u[4]; } bulk = {};
	bulk.p = thread;
	return (bulk.u[0] ^ bulk.u[1]) ^ (bulk.u[2] ^ bulk.u[3]);
}

static guint16
get_thread_id(void)
{
	return compute_thread_id(g_thread_self());
}

static int
glvl_to_lvl(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
		case G_LOG_LEVEL_CRITICAL:
			return LOG_ERR;
		case G_LOG_LEVEL_WARNING:
			return LOG_WARNING;
		case G_LOG_LEVEL_MESSAGE:
			return LOG_NOTICE;
		case G_LOG_LEVEL_INFO:
		case G_LOG_LEVEL_DEBUG:
			return LOG_INFO;
		default:
			break;
	}
	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return LOG_ERR;
		case 2:
			return LOG_WARNING;
		case 4:
			return LOG_NOTICE;
		case 8:
			return LOG_INFO;
		default:
			return LOG_DEBUG;
	}
}

static inline const gchar*
glvl_to_str(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return "ERR";
		case G_LOG_LEVEL_CRITICAL:
			return "CRI";
		case G_LOG_LEVEL_WARNING:
			return "WRN";
		case G_LOG_LEVEL_MESSAGE:
			return "NOT";
		case G_LOG_LEVEL_INFO:
			return "INF";
		case G_LOG_LEVEL_DEBUG:
			return "DBG";
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return "ERR";
		case 2:
			return "WRN";
		case 4:
			return "NOT";
		case 8:
			return "INF";
		case 16:
			return "DBG";
		case 32:
			return "TR0";
		default:
			return "TR1";
	}
}

static void
_append_message(GString *gstr, const gchar *msg)
{
	if (!msg)
		return;
	// skip leading blanks
	for (; *msg && g_ascii_isspace(*msg) ;msg++) {}
	g_string_append(gstr, msg);
}

static void
logger_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	(void) user_data;

	if (!glvl_allowed(log_level))
		return;

	GString *gstr = g_string_new("");

	g_string_append_printf(gstr, "%d %04X", getpid(), get_thread_id());

	if (!log_domain || !*log_domain)
		log_domain = "-";
	g_string_append(gstr, " log ");
	g_string_append(gstr, glvl_to_str(log_level));
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, log_domain);

	g_string_append_c(gstr, ' ');

	_append_message(gstr, message);

	syslog(glvl_to_lvl(log_level), "%s", gstr->str);
	g_string_free(gstr, TRUE);
}

static void
logger_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	struct timeval tv;
	GString *gstr;

	(void) user_data;

	if (!glvl_allowed(log_level))
		return;

	gstr = g_string_sized_new(256);
	gettimeofday(&tv, NULL);

	g_string_append_printf(gstr, "%ld.%03ld %d %04X ",
			tv.tv_sec, tv.tv_usec/1000,
			getpid(), get_thread_id());

	if (!log_domain || !*log_domain)
		log_domain = "-";

	g_string_append_printf(gstr, "log %s %s %s\n", glvl_to_str(log_level), log_domain, message);
	fwrite(gstr->str, gstr->len, 1, stderr);
	g_string_free(gstr, TRUE);
}

static void
__parse_options(int argc, char ** args)
{
	GError *error_local = NULL;
	GOptionContext *context = g_option_context_new(" CONFIG_PATH [LOG4C_PATH]");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &args, &error_local)) {
		g_print("option parsing failed: %s\n", error_local->message);
		gchar *usage = g_option_context_get_help (context, TRUE, NULL);
		g_print("%s", usage);
		exit(1);
		return;
	}

	if (flag_more_verbose)
		logger_verbose_default();

	if (flag_version) {
		fprintf(stdout, "gridinit version: %s\n", API_VERSION);
		exit(0);
		return;
	}
	/* check for additionnal arguments */
	if (optind >= argc) {
		gchar *usage = g_option_context_get_help (context, TRUE, NULL);
		g_print("%s", usage);
		exit(1);
		return;
	}
	g_option_context_free(context);
	context = NULL;

	if (*syslog_id) {
		openlog(g_get_prgname(), LOG_PID, LOG_LOCAL0);
		g_log_set_default_handler(logger_syslog, NULL);
	}

	/* configuration loading */
	config_path = g_strdup(args[optind]);
	if (!flag_quiet)
		DEBUG("Reading the config from [%s]", config_path);
	if (!_cfg_reload(FALSE, &error_local)) {
		if (!flag_quiet)
			ERROR("Configuration loading error from [%s] : %s\n", config_path, error_local->message);
		exit(1);
	}
}

static void
write_pid_file(void)
{
	FILE *stream_pidfile;

	if (!*pidfile_path)
		return ;

	stream_pidfile = fopen(pidfile_path, "w+");
	if (!stream_pidfile) {
		ERROR("write_pid_file() error : [%s] : %s", pidfile_path, strerror(errno));
		return ;
	}

	fprintf(stream_pidfile, "%d", getpid());
	fclose(stream_pidfile);
	NOTICE("Wrote PID in [%s]", pidfile_path);
}

static gboolean
is_gridinit_running(const gchar *path)
{
	int rc, usock;
	struct sockaddr_un sun = {};

	sun.sun_family = AF_UNIX;
	g_strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (0 > (usock = socket(PF_UNIX, SOCK_STREAM, 0)))
		return FALSE;

	rc = connect(usock, (struct sockaddr*)&sun, sizeof(sun));
	close(usock);
	usock = -1;

	if (rc == 0)
		return TRUE;
	if (errno != ECONNREFUSED && errno != ENOENT) {
		/* This can be EACCES for bad rights/permissions, EINVAL for
		 * a design error. */
		return TRUE;
	}

	if (unlink(path) == 0) {
		NOTICE("Removing stalled socket [%s]", path);
	}
	else if (errno != ENOENT) {
		g_printerr("Failed to remove stalled socket [%s] : %s", path, strerror(errno));
		WARN("Failed to remove stalled socket [%s] : %s", path, strerror(errno));
	}

	return FALSE;
}

static void _signal_handler(int s)
{
	switch (s) {
	case SIGUSR1:
		flag_more_verbose = ~0;
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGKILL:
	case SIGTERM:
		flag_running = 0;
		return;
	case SIGUSR2:
	case SIGPIPE:
	case SIGCHLD:
	case SIGALRM:
		return;
	}
}

static int
_action(void)
{
	int rc, ch[2] = {-1, -1};

	rc = dill_chmake(ch);
	if (rc != 0)
		return rc;

	rc = dill_chdone(ch[1]);  /* one way only */
	if (rc != 0)
		goto label_error;

	/* Kickoff the network service */
	int ldr_server = dill_go(_server_run(ch[0], sock_path));
	if (ldr_server < 0) {
		ERROR("Failed to kickoff the server coroutine: (%d) %s",
				errno, strerror(errno));
		rc = -1;
		goto label_error;
	} else {
		DEBUG("Started the server coroutine h=%d", ldr_server);
	}

	/* start all the enabled processes, then run the main loop */
	rc = 0;
	guint proc_count = supervisor_children_start_enabled(NULL, NULL);
	DEBUG("First started %u processes", proc_count);

	_routine_check(ch[1]);
	rc = 0;

	/* Stop the server coroutine and handle */
	DEBUG("Stopping the server");
	if (ldr_server >= 0) {
		dill_hclose(ldr_server);
		ldr_server = -1;
	}

label_error:
	dill_chdone(ch[0]);
	dill_hclose(ch[0]);
	dill_hclose(ch[1]);
	return rc;
}

int
main(int argc, char ** args)
{
	int rc = 1;

	gq_log = g_quark_from_static_string(LOG_DOMAIN);

	logger_init_level(GRID_LOGLVL_INFO);
	g_log_set_default_handler(logger_stderr, NULL);
	g_set_prgname(args[0]);
	supervisor_children_init();
	__parse_options(argc, args);
	freopen("/dev/null", "r", stdin);

	if (is_gridinit_running(sock_path)) {
		FATAL("A gridinit is probably already running,"
			" someone listens to UNIX sock path [%s]", sock_path);
		goto label_exit;
	}

	if (flag_daemon || *syslog_id) {
		freopen( "/dev/null", "w", stdout);
		freopen( "/dev/null", "w", stderr);
	}

	if (flag_daemon) {
		if (0 != daemon(1,0)) {
			FATAL("Failed to daemonize : %s", strerror(errno));
			goto label_exit;
		}
		write_pid_file();
	}

	/* Signal management */
	signal(SIGTERM, _signal_handler);
	signal(SIGABRT, _signal_handler);
	signal(SIGINT, _signal_handler);
	signal(SIGALRM, _signal_handler);
	signal(SIGQUIT, _signal_handler);
	signal(SIGUSR1, _signal_handler);
	signal(SIGPIPE, _signal_handler);
	signal(SIGUSR2, _signal_handler);
	signal(SIGCHLD, _signal_handler);

	rc = _action();

label_exit:
	thread_ignore_signals();

	DEBUG("Stopping all the children");
	(void) supervisor_children_stopall(1);

	DEBUG("Waiting for them to die");
	while (supervisor_children_kill_disabled() > 0)
		sleep(1);

	DEBUG("Cleaning the working structures");
	supervisor_children_cleanall();
	supervisor_children_fini();

	g_free(config_path);
	if (*pidfile_path) {
		unlink(pidfile_path);
	}
	closelog();
	return rc;
}

