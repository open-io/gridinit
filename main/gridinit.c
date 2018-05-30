/*
gridinit, a monitor for non-daemon processes.
Copyright (C) 2013 AtoS Worldline, original work aside of Redcurrant
Copyright (C) 2015 OpenIO, modified for OpenIO Software Defined Storage

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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit.main"
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <syslog.h>
#include <glob.h>

#include <event.h>
#include <glib.h>

#include <gridinit-utils.h>
#include "./gridinit_internals.h"
#include "./gridinit_alerts.h"
#include "../lib/gridinit-internals.h"

#define USERFLAG_ONDIE_EXIT        0x00000001
#define USERFLAG_PROCESS_DIED      0x00000002
#define USERFLAG_PROCESS_RESTARTED 0x00000004

#define BOOL(i) ((i)!=0)

typedef int (*cmd_f)(struct bufferevent *bevent, int argc, char **argv);

struct cmd_mapping_s {
	const gchar *cmd_name;
	cmd_f cmd_callback;
};

struct server_sock_s {
	int family;
	int fd;
	char *url;
	struct event event;
	struct stat unix_stat_path;
	struct stat unix_stat_sock;
};

int main_log_level_default = 0x7F;
int main_log_level = 0x7F;
gint64 main_log_level_update = 0;

static GList *list_of_servers = NULL;
static GList *list_of_signals = NULL; /* list of libevent events */

static char syslog_id[256] = "";
static char sock_path[1024] = "";
static char pidfile_path[1024] = "";
static char default_working_directory[1024] = "";
static char *config_path = NULL;
static char *config_subdir = NULL;

static char **groups_only_cli = NULL;
static char **groups_only_cfg = NULL;

static volatile int flag_help = 0;
static volatile int flag_quiet = 0;
static volatile int flag_daemon = 0;
static volatile int flag_running = ~0;
static volatile int flag_check_socket = 0;
static volatile int flag_more_verbose = 0;

static volatile gint32 default_uid = -1;
static volatile gint32 default_gid = -1;

static volatile gboolean inherit_env = 0;

static GHashTable *default_env = NULL;

static gboolean _cfg_reload(gboolean services_only, GError **err);

static void servers_ensure(void);


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

static struct event timer_event;

static void timer_event_arm(gboolean first);
static void timer_event_cb(int i, short s, void *p);

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

static void
timer_event_cb(int i, short s, void *p)
{
	(void)i;
	(void)s;
	(void)p;
	timer_event_arm(FALSE);
}

static void
timer_event_arm(gboolean first)
{
	struct timeval tv;
	if (first)
		evtimer_set(&timer_event, timer_event_cb, NULL);
	tv.tv_sec = tv.tv_usec = 1L;
	evtimer_add(&timer_event, &tv);
}

/* Process management helpers ---------------------------------------------- */

static void
alert_proc_died(void *udata, struct child_info_s *ci)
{
	(void) udata;

	/* if the user_flags on the process contain the on_die:exit flag,
	 * then we mark the gridinit to stop */
	if (ci->user_flags & USERFLAG_ONDIE_EXIT) {
		supervisor_children_enable(ci->key, FALSE);
		flag_running = FALSE;
	}

	if (ci->started)
		supervisor_children_set_user_flags(ci->key, USERFLAG_PROCESS_DIED);
}

static void
alert_send_deferred(void *udata, struct child_info_s *ci)
{
	(void) udata;
	gchar buff[1024];

	/* Handle the alerting of broken services */
	if ((ci->user_flags & USERFLAG_PROCESS_DIED) && ci->broken) {
		supervisor_children_del_user_flags(ci->key, USERFLAG_PROCESS_DIED);
		g_snprintf(buff, sizeof(buff), "Process broken [%s] %s", ci->key, ci->cmd);
		gridinit_alerting_send(GRIDINIT_EVENT_BROKEN, buff);
	}

	/* Handle the alerting of successfully restarted services */
	if (!(ci->user_flags & USERFLAG_PROCESS_DIED) && (ci->user_flags & USERFLAG_PROCESS_RESTARTED)) {
		supervisor_children_del_user_flags(ci->key, USERFLAG_PROCESS_RESTARTED);
		g_snprintf(buff, sizeof(buff), "Process restarted [%s] %s", ci->key, ci->cmd);
		gridinit_alerting_send(GRIDINIT_EVENT_RESTARTED, buff);
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
service_run_groupv(int nb_groups, char **groupv, void *udata, supervisor_cb_f cb)
{
	guint count;
	struct bufferevent *bevent;

	void group_filter(void *u1, struct child_info_s *ci) {
		if (!gridinit_group_in_set((gchar*)u1, ci->group)) {
			TRACE("start: Skipping [%s] with group [%s]", ci->key, ci->group);
			return;
		}
		TRACE("Calback on service [%s]", ci->key);
		cb(udata, ci);
		++ count;
	}

	bevent = udata;

	if (!nb_groups || !groupv)
		supervisor_run_services(NULL, cb);
	else {
		int i;
		char *what;
		struct child_info_s ci;

		for (i=0; i<nb_groups ;i++) {
			what = groupv[i];
			if (*what == '@') {
				TRACE("Callback on group [%s]", what);
				count = 0;
				supervisor_run_services(what+1, group_filter);
				if (!count && bevent) {
					/* notifies the client the group has not been found */
					evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", ENOENT, what);
				}
			}
			else {
				bzero(&ci, sizeof(ci));
				if (0 == supervisor_children_get_info(what, &ci)) {
					TRACE("Calback on service [%s]", what);
					cb(udata, &ci);
				}
				else {
					if (bevent)
						evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", errno, what);
					if (errno == ENOENT)
						TRACE("Service not found [%s]\n", what);
					else
						ERROR("Internal error [%s] : %s", what, strerror(errno));
				}
			}
		}
	}
}

static int
command_start(struct bufferevent *bevent, int argc, char **argv)
{
	void start_process(void *udata, struct child_info_s *ci) {
		(void) udata;

		supervisor_children_repair(ci->key);

		switch (supervisor_children_status(ci->key, TRUE)) {
		case 0:
			INFO("Already started [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", EALREADY, ci->key);
			return;
		case 1:
			INFO("Started [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", 0, ci->key);
			return;
		default:
			WARN("Cannot start [%s] : %s", ci->key, strerror(errno));
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", errno, ci->key);
			return;
		}
	}

	service_run_groupv(argc, argv, bevent, start_process);
	bufferevent_enable(bevent, EV_WRITE);
	bufferevent_flush(bevent, EV_WRITE, BEV_FINISHED);
	return 0;
}

static int
command_stop(struct bufferevent *bevent, int argc, char **argv)
{
	void stop_process(void *udata, struct child_info_s *ci) {
		(void) udata;
		switch (supervisor_children_status(ci->key, FALSE)) {
		case 0:
			INFO("Already stopped [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", EALREADY, ci->key);
			return;
		case 1:
			INFO("Stopped [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", 0, ci->key);
			return;
		default:
			WARN("Cannot stop [%s] : %s", ci->key, strerror(errno));
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", errno, ci->key);
			return;
		}
	}

	service_run_groupv(argc, argv, bevent, stop_process);
	bufferevent_enable(bevent, EV_WRITE);
	bufferevent_flush(bevent, EV_WRITE, BEV_FINISHED);
	return 0;
}

static int
command_restart(struct bufferevent *bevent, int argc, char **argv)
{
	void restart_process(void *udata, struct child_info_s *ci) {
		(void) udata;
		switch (supervisor_children_restart(ci->key)) {
		case 0:
			INFO("Already restarted [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", EALREADY, ci->key);
			return;
		case 1:
			INFO("Restart [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", 0, ci->key);
			return;
		default:
			WARN("Cannot restart [%s] : %s", ci->key, strerror(errno));
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", errno, ci->key);
			return;
		}
	}

	service_run_groupv(argc, argv, bevent, restart_process);
	bufferevent_enable(bevent, EV_WRITE);
	bufferevent_flush(bevent, EV_WRITE, BEV_FINISHED);
	return 0;
}


static int
command_show(struct bufferevent *bevent, int argc, char **argv)
{
	void print_process(void *udata, struct child_info_s *ci) {
		(void) udata;
		evbuffer_add_printf(bufferevent_get_output(bevent),
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

	(void) argc;
	(void) argv;

	service_run_groupv(0, NULL, NULL, print_process);
	bufferevent_enable(bevent, EV_WRITE);
	bufferevent_flush(bevent, EV_WRITE, BEV_FINISHED);
	return 0;
}

static int
command_repair(struct bufferevent *bevent, int argc, char **argv)
{
	void repair_process(void *udata, struct child_info_s *ci) {
		(void) udata;
		if (0 == supervisor_children_repair(ci->key)) {
			INFO("Repaired [%s]", ci->key);
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", 0, ci->key);
		}
		else {
			WARN("Failed to repair [%s] : %s", ci->key, strerror(errno));
			evbuffer_add_printf(bufferevent_get_output(bevent), "%d %s\n", errno, ci->key);
		}
	}

	service_run_groupv(argc, argv, bevent, repair_process);
	bufferevent_enable(bevent, EV_WRITE);
	bufferevent_flush(bevent, EV_WRITE, BEV_FINISHED);
	return 0;
}

static int
command_reload(struct bufferevent *bevent, int argc, char **argv)
{
	GError *error_local = NULL;
	guint count;

	(void) argc;
	(void) argv;

	count = supervisor_children_mark_obsolete();
	TRACE("Marked %u obsolete services\n", count);
	evbuffer_add_printf(bufferevent_get_output(bevent), "%d obsoleted %u processes\n", 0, count);

	if (!_cfg_reload(TRUE, &error_local)) {
		WARN("error: Failed to reload the configuration from [%s]\n", config_path);
		WARN("cause: %s\n", error_local ? error_local->message : "NULL");
		evbuffer_add_printf(bufferevent_get_output(bevent), "%d reload\n", error_local ? error_local->code : EINVAL);
	}
	else {
		evbuffer_add_printf(bufferevent_get_output(bevent), "0 reload\n");

		count = supervisor_children_disable_obsolete();
		evbuffer_add_printf(bufferevent_get_output(bevent), "0 disabled %u obsolete processes\n", count);

		if (count)
			NOTICE("Services refreshed, %u disabled\n", count);
		else
			TRACE("Services refreshed, %u disabled\n", count);

	}
	return 0;
}

static struct cmd_mapping_s COMMANDS [] = {
	{"status",  command_show },
	{"repair",  command_repair },
	{"start",   command_start },
	{"stop",    command_stop },
	{"restart", command_restart },
	{"reload",  command_reload },
	{NULL,      NULL}
};

static cmd_f
__resolve_command(const gchar *n)
{
	int i;
	for (i=0; ;i++) {
		struct cmd_mapping_s *cmd = COMMANDS + i;
		if (!cmd->cmd_name)
			return NULL;
		if (0 == g_ascii_strcasecmp(n, cmd->cmd_name))
			return cmd->cmd_callback;
	}
}


/* Libevent callbacks ------------------------------------------------------ */

static void
supervisor_signal_handler(int s, short flags, void *udata)
{
	(void) udata, (void) flags;

	switch (s) {
	case SIGUSR1:
		flag_more_verbose = ~0;
		return;
	case SIGUSR2:
		flag_check_socket = ~0;
		return;
	case SIGPIPE: /* ignored */
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGKILL:
	case SIGTERM:
		flag_running = 0;
		return;
	case SIGCHLD:
		return;
	case SIGALRM:
		return;
	}
}

static void
__bevent_error(struct bufferevent *bevent, short what, void *udata)
{
	(void) udata;
	if (what & BEV_EVENT_CONNECTED) {
		TRACE("Connection established for fd=%d what=%04X", bufferevent_getfd(bevent), what);
		bufferevent_enable(bevent, EV_READ|EV_WRITE);
	}
	if (what & ~BEV_EVENT_CONNECTED) {
		int fd, sock_err;
		socklen_t sock_err_len;

		fd = bufferevent_getfd(bevent);
		sock_err_len = sizeof(sock_err);
		if (0 != getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_len))
			TRACE("Error on fd=%d what=%04X : getsockopt() error : %s", fd, what, strerror(errno));
		else
			TRACE("Error on fd=%d what=%04X : %s", fd, what, strerror(sock_err));
		bufferevent_flush(bevent, EV_READ,  BEV_FINISHED);
		bufferevent_flush(bevent, EV_WRITE, BEV_FINISHED);
		bufferevent_enable(bevent, EV_READ|EV_WRITE);
	}
}

static void
__event_command_in(struct bufferevent *bevent, void *udata)
{
	int argc = 0;
	gchar **argv = NULL;
	char *cmd;
	size_t cmd_len = 0;

	(void) udata;
	TRACE("Data available from fd=%d", bufferevent_getfd(bevent));

	cmd = evbuffer_readln(bufferevent_get_input(bevent), &cmd_len, EVBUFFER_EOL_CRLF);
	if (!cmd) {
		TRACE("Read error from fd=%d", bufferevent_getfd(bevent));
		bufferevent_disable(bevent, EV_WRITE);
		bufferevent_enable(bevent,  EV_READ);
		return;
	}
	else {
		cmd_f callback;

		if (!g_shell_parse_argv(cmd, &argc, &argv, NULL))
			TRACE("Invalid request from fd=%d", bufferevent_getfd(bevent));
		else {
			TRACE("Executing request [%s] from fd=%d", argv[0], bufferevent_getfd(bevent));
			if (NULL != (callback = __resolve_command(argv[0])))
				(callback)(bevent, argc-1, argv+1);
			g_strfreev(argv);
		}
		free(cmd);

		bufferevent_flush(bevent, EV_WRITE|EV_READ, BEV_FINISHED);
		bufferevent_disable(bevent, EV_READ);
		bufferevent_enable(bevent, EV_WRITE);
	}
}

static void
__event_command_out(struct bufferevent *bevent, void *udata)
{
	(void) udata;
	TRACE("Closing client connection fd=%d", bufferevent_getfd(bevent));
	bufferevent_disable(bevent, EV_READ|EV_WRITE);
	close(bufferevent_getfd(bevent));
	bufferevent_setfd(bevent, -1);
	bufferevent_free(bevent);
}

static void
__event_accept(int fd, short flags, void *udata)
{
	struct bufferevent *bevent =  NULL;
	struct linger ls = {1,0};
	socklen_t ss_len;
	struct sockaddr_storage ss;
	int fd_client;
	int i_opt, i_rc;
	struct event_base *libevents_handle;

	(void) flags;
	libevents_handle = udata;

	ss_len = sizeof(ss);
	fd_client = accept(fd, (struct sockaddr*)&ss, &ss_len);
	if (fd_client < 0) {
		WARN("accept error on fd=%d : %s", fd, strerror(errno));
		return;
	}

	/*SO_LINGER*/
	ls.l_onoff = 1;
	ls.l_linger = 0;
	i_rc = setsockopt(fd_client, SOL_SOCKET, SO_LINGER, (void *) &ls, sizeof(ls));
	if (i_rc == -1)
		WARN("fd=%i Cannot set the linger behaviour (%s)", fd_client, strerror(errno));

	/*SO_REUSEADDR*/
	i_opt = 1;
	i_rc = setsockopt(fd_client, SOL_SOCKET, SO_REUSEADDR, (void*) &i_opt, sizeof(i_opt));
	if (i_rc == -1)
		WARN("fd=%i Cannot set the REUSEADDR flag (%s)", fd_client, strerror(errno));

	/*SO_KEEPALIVE*/
	i_opt = 1;
	i_rc = setsockopt(fd_client, SOL_SOCKET, SO_KEEPALIVE, (void*) &i_opt, sizeof(i_opt));
	if (i_rc == -1)
		WARN("fd=%i Cannot trigger the tcp keepalive behaviour (%s)", fd_client, strerror(errno));

	/* TCP-specific options */
	socklen_t opt_len = sizeof(i_opt);
	i_rc = getsockopt(fd_client, SOL_SOCKET, SO_TYPE, (void*)&i_opt, &opt_len);
	if (i_rc == -1)
		WARN("fd=%i Cannot check the socket type (%s)", fd_client, strerror(errno));
	else if (i_opt == SOCK_STREAM && ss.ss_family == AF_INET) {

		/* TCP_QUICKACK */
		i_opt = 1;
		i_rc = setsockopt(fd_client, IPPROTO_TCP, TCP_QUICKACK, (void*)&i_opt, sizeof(i_opt));
		if (i_rc == -1)
			WARN("fd=%i Cannot set TCP_QUICKACK mode on socket (%s)", fd_client, strerror(errno));

		/* TCP_NODELAY */
		i_opt = 1;
		i_rc = setsockopt(fd_client, IPPROTO_TCP, TCP_NODELAY, (void*)&i_opt, sizeof(i_opt));
		if (i_rc == -1)
			WARN("fd=%i Cannot set TCP_NODELAY mode on socket (%s)", fd_client, strerror(errno));
	}

	evutil_make_socket_closeonexec(fd_client);

	/* Now manage this connection */
	bevent = bufferevent_new(fd_client, __event_command_in, __event_command_out, __bevent_error, NULL);
	bufferevent_settimeout(bevent, 1000, 4000);
	bufferevent_enable(bevent, EV_READ);
	bufferevent_disable(bevent, EV_WRITE);
	bufferevent_base_set(libevents_handle, bevent);
	TRACE("Connection accepted server=%d client=%d", fd, fd_client);
}


/* Server socket pool management ------------------------------------------- */

static int
servers_is_unix(struct server_sock_s *server)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;

	bzero(&ss, sizeof(ss));
	ss_len = sizeof(ss);

	if (server->fd < 0)
		return FALSE;

	if (0 == getsockname(server->fd, (struct sockaddr*) &ss, &ss_len)) {
		if (ss.ss_family==AF_UNIX || ss.ss_family==AF_LOCAL) {
			return TRUE;
		}
	}

	errno = 0;
	return FALSE;
}

static int
servers_is_the_same(struct server_sock_s *server)
{
	struct stat stat_sock, stat_path;

	bzero(&stat_sock, sizeof(stat_sock));
	bzero(&stat_path, sizeof(stat_path));

	return ((0 == stat(server->url, &stat_path))
			&& (0 == fstat(server->fd, &stat_sock))
			&& (stat_path.st_ino == server->unix_stat_path.st_ino)
			&& (stat_sock.st_ino == server->unix_stat_sock.st_ino));
}

static void
servers_unmonitor_one(struct server_sock_s *server)
{
	if (server->fd < 0) {
		/* server socket already stopped */
		return ;
	}

	/* Stop the libevent management right now */
	if (event_pending(&(server->event), EV_READ, NULL))
		event_del(&(server->event));

	/* If the current socket is a UNIX socket, remove the socket file
	 * on disk only if this file is exactly the same that the file
	 * this socket created. We must avoid deleting a socket file
	 * opened by another process */
	if (servers_is_unix(server) && servers_is_the_same(server))
		unlink(server->url);

	shutdown(server->fd, SHUT_RDWR);
	close(server->fd);
	server->fd = -1;
}

/* starts the server monitoring with the libevent.
 * The inner file descriptor must be a valid socket filedes */
static gboolean
servers_monitor_one(struct server_sock_s *server)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;

	if (!server || server->fd < 0) {
		errno = EINVAL;
		return FALSE;
	}

	memset(&ss, 0x00, sizeof(ss));
	ss_len = sizeof(ss);
	if (-1 == getsockname(server->fd, (struct sockaddr*) &ss, &ss_len)) {
		if (!flag_quiet)
			g_printerr("Error with socket [%s]\n", server->url);
		return FALSE;
	}

	/* For unix sockets, remember the stat for further checks */
	if (ss.ss_family==AF_UNIX || ss.ss_family==AF_LOCAL) {
		if (0 != stat(((struct sockaddr_un*)&ss)->sun_path, &(server->unix_stat_path))) {
			if (!flag_quiet)
				g_printerr("Error with socket [%s]\n", server->url);
			return FALSE;
		}
		if (0 != fstat(server->fd, &(server->unix_stat_sock))) {
			if (!flag_quiet)
				g_printerr("Error with socket [%s]\n", server->url);
			return FALSE;
		}
	}

	event_set(&(server->event), server->fd, EV_READ|EV_PERSIST, __event_accept, NULL);
	event_add(&(server->event), NULL);
	errno = 0;
	if (!flag_quiet)
		g_printerr("Socket opened [%s]\n", server->url);
	return TRUE;
}

static int
servers_monitor_none(void)
{
	GList *l;

	TRACE("About to stop all the server sockets");
	for (l=list_of_servers; l ;l=l->next) {
		struct server_sock_s *s = l->data;
		servers_unmonitor_one(s);
	}

	errno = 0;
	return TRUE;
}

static int
servers_monitor_all(void)
{
	GList *l;

	TRACE("About to monitor all the server sockets");

	for (l=list_of_servers; l ;l=l->next) {
		struct server_sock_s *s = l->data;
		if (!servers_monitor_one(s))
			return FALSE;
	}

	errno = 0;
	return TRUE;
}

/**
 * Creates a server structure based on the file descriptor and
 * add it to the list
 */
static gboolean
servers_save_fd(int fd, const char *url)
{
	struct server_sock_s *server;

	if (fd < 0)
		return FALSE;

	/* should check if the socket is not already monitored */
	server = g_malloc0(sizeof(*server));
	server->fd = fd;
	server->url = g_strdup(url);

	list_of_servers = g_list_prepend(list_of_servers, server);
	return TRUE;
}

/**
 * Opens a UNIX server socket then manage a server based on it
 */
static int
servers_save_unix(const char *path)
{
	int sock;

	if (-1 == (sock = __open_unix_server(path)))
		goto label_error;

	if (!servers_save_fd(sock, path))
		goto label_error;

	errno = 0;
	return sock;

label_error:
	if (sock >= 0) {
		typeof(errno) errsav;
		errsav = errno;
		shutdown(sock, SHUT_RDWR);
		close(sock);
		errno = errsav;
	}
	return -1;
}

/**
 * Stops the server socket then
 */
static void
servers_clean(void)
{
	GList *l;

	/* stop */
	servers_monitor_none();

	/* clean */
	for (l=list_of_servers; l ; l=l->next) {
		struct server_sock_s *p_server = l->data;

		if (p_server->url)
			g_free(p_server->url);

		memset(p_server, 0x00, sizeof(*p_server));
		g_free(p_server);
		l->data = NULL;
	}

	g_list_free(list_of_servers);
	list_of_servers = NULL;
}

/**
 * Reopens all the UNIX server sockets bond on paths that changed.
 */
static void
servers_ensure(void)
{
	GList *l;

	flag_check_socket = 0;
	TRACE("About to ensure the server sockets");

	for (l=list_of_servers; l ; l=l->next) {
		struct server_sock_s *p_server = l->data;

		NOTICE("Ensuring socket fd=%d bond to [%s]", p_server->fd, p_server->url);

		if (servers_is_unix(p_server) && !servers_is_the_same(p_server)) {

			/* close */
			servers_unmonitor_one(p_server);

			/* reopen */
			p_server->fd = __open_unix_server(p_server->url);
			if (p_server->fd < 0) {
				WARN("unix: failed to reopen a server bond to [%s] : %s",
						p_server->url, strerror(errno));
			}
			else if (!servers_monitor_one(p_server)) {
				WARN("unix: failed to monitor a server bond to [%s] : %s",
						p_server->url, strerror(errno));
				servers_unmonitor_one(p_server);
			}
		}
	}
}

/* Signals management ------------------------------------------------------ */

static void
signals_manage(int s)
{
	struct event *signal_event;
	signal_event = g_malloc0(sizeof(*signal_event));
	event_set(signal_event, s, EV_SIGNAL|EV_PERSIST, supervisor_signal_handler, NULL);
	event_add(signal_event, NULL);
	list_of_signals = g_list_prepend(list_of_signals, signal_event);
}

static void
signals_clean(void)
{
	GList *l;
	for (l=list_of_signals; l ;l=l->next) {
		struct event *signal_event = l->data;
		g_free(signal_event);
		l->data = NULL;
	}
	g_list_free(list_of_signals);
	list_of_signals = NULL;
}

/* Configuration ----------------------------------------------------------- */

static void
main_usage(void)
{
	if (flag_quiet)
		return;
	g_printerr("\n"
		"Usage: %s [OPTIONS] ... CONFIG_PATH [LOG4C_PATH]\n"
		" with OPTIONS:\n"
		"    -d       : Detaches then daemonizes the gridinit\n"
		"    -h       : displays this help section\n"
		"    -g GROUP : limits the services loading to those belonging to\n"
		"               the specified group. This option can be repeated.\n"
		"    -q       : quiet mode, suppress non-error output\n"
		"\n", g_get_prgname());
}

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
	gchar **p_group, **which;

	if (!groups_only_cli && !groups_only_cfg) {
		TRACE("Service [%s] accepted : gridinit not restricted to some groups", str_key);
		return TRUE;
	}
	if (!str_group) {
		DEBUG("Service [%s] ignored : no group provided", str_key);
		return FALSE;
	}

	which = groups_only_cli ? groups_only_cli : groups_only_cfg;
	for (p_group=which; *p_group ;p_group++) {
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
	struct child_info_s ci;

	bzero(&ci, sizeof(ci));
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
			*err = g_error_printf(LOG_DOMAIN, EINVAL, "Service [%s] cannot cannot receive UID [%s] : errno=%d %s",
		                        str_key, str_uid, errno, strerror(errno));
			goto label_exit;
		}
		if (!gid_exists(str_gid, &gid)) {
			/* Invalid group */
			*err = g_error_printf(LOG_DOMAIN, EINVAL, "Service [%s] cannot cannot receive GID [%s] : errno=%d %s",
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
		*err = g_error_printf(LOG_DOMAIN, errno, "Service [%s] cannot be marked [%s] : %s",
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

	/* on_die management. Respawn, cry, or abort */
	if (str_ondie) {
		if (0 == g_ascii_strcasecmp(str_ondie, "cry")) {
			if (0 > supervisor_children_set_respawn(str_key, FALSE))
				WARN("Failed to make [%s] respawn : %s", str_key, strerror(errno));
		}
		else if (0 == g_ascii_strcasecmp(str_ondie, "exit")) {
			supervisor_children_set_user_flags(str_key, USERFLAG_ONDIE_EXIT);
			supervisor_children_set_respawn(str_key, FALSE);
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
_cfg_section_alert(GKeyFile *kf, const gchar *section, GError **err)
{
	gchar cfg_plugin[1024], cfg_symbol[128];
	gchar **p_key, **keys;

	bzero(cfg_plugin, sizeof(cfg_plugin));
	bzero(cfg_symbol, sizeof(cfg_symbol));

	keys = g_key_file_get_keys(kf, section, NULL, err);
	if (!keys)
		return FALSE;

	for (p_key=keys; *p_key ;p_key++) {
		gchar *str;

		str = g_key_file_get_string(kf, section, *p_key, NULL);

		if (!g_ascii_strcasecmp(*p_key, "plugin")) {
			if (*cfg_plugin)
				NOTICE("Alerting plugin already known : plugin=[%s]", cfg_plugin);
			else
				g_strlcpy(cfg_plugin, str, sizeof(cfg_plugin)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, "symbol")) {
			if (*cfg_symbol)
				NOTICE("Alerting symbol already known : symbol=[%s]", cfg_symbol);
			else
				g_strlcpy(cfg_symbol, str, sizeof(cfg_symbol)-1);
		}

		g_free(str);
	}

	g_strfreev(keys);

	if (!*cfg_symbol || !*cfg_plugin) {
		WARN("Missing configuration keys : both \"plugin\" and \"symbol\""
			" must be present in section [%s]", section);
		return FALSE;
	}
	else {
		GHashTable *ht_params;
		gboolean rc;
		ht_params = _cfg_extract_parameters(kf, section, "config.", err);
		rc = gridinit_alerting_configure(cfg_plugin, cfg_symbol, ht_params, err);
		g_hash_table_destroy(ht_params);
		if (!rc)
			return FALSE;
	}

	return TRUE;
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
			bzero(default_working_directory, sizeof(default_working_directory));
			g_strlcpy(default_working_directory, str, sizeof(default_working_directory)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_PATH_PIDFILE)) {
			bzero(pidfile_path, sizeof(pidfile_path));
			g_strlcpy(pidfile_path, str, sizeof(pidfile_path)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LISTEN)) {
			if (str[0] == '/')
				g_strlcpy(sock_path, str, sizeof(sock_path));
			else
				g_printerr("section=%s, key=listen : not a UNIX path, ignored! [%s]\n",
					section, str);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_USER)) {
			bzero(buf_user, sizeof(buf_user));
			g_strlcpy(buf_user, str, sizeof(buf_user)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_GROUP)) {
			bzero(buf_group, sizeof(buf_group));
			g_strlcpy(buf_group, str, sizeof(buf_group)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_UID)) {
			bzero(buf_uid, sizeof(buf_uid));
			g_strlcpy(buf_uid, str, sizeof(buf_uid)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_GID)) {
			bzero(buf_gid, sizeof(buf_gid));
			g_strlcpy(buf_gid, str, sizeof(buf_gid)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_INCLUDES)) {
			bzero(buf_includes, sizeof(buf_includes));
			g_strlcpy(buf_includes, str, sizeof(buf_includes)-1);
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
	gchar **groups=NULL, **p_group=NULL;

	groups = g_key_file_get_groups(kf, NULL);

	if (!groups) {
		*err = g_error_new(g_quark_from_static_string("gridinit"), EINVAL, "no group");
		return FALSE;
	}

	for (p_group=groups; *p_group ;p_group++) {

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
		else if (!services_only && !g_ascii_strcasecmp(*p_group, "alerts")) {
			INFO("reconfigure : loading alerting parameters from section [%s]", *p_group);
			if (!_cfg_section_alert(kf, *p_group, err)) {
				WARN("Invalid alerts section");
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
	GKeyFile *kf = NULL;

	kf = g_key_file_new();

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
		int glob_rc;
		glob_t subfiles_glob;

		bzero(&subfiles_glob, sizeof(subfiles_glob));

		DEBUG("Loading services files matching [%s]", config_subdir);

		glob_rc = glob(config_subdir, GLOB_NOSORT|GLOB_MARK, notify_error, &subfiles_glob);
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
	union {
		void *p;
		guint16 u[4];
	} bulk;
	memset(&bulk, 0, sizeof(bulk));
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
	int c;
	GError *error_local = NULL;

	while (-1 != (c = getopt(argc, args, "vqhdg:s:"))) {
		switch (c) {
			case 'd':
				flag_daemon = ~0;
				break;
			case 'h':
				flag_help = ~0;
				break;
			case 'g':
				if (!optarg) {
					g_printerr("Expected argument to the '-%c' option\n", c);
					exit(1);
				}
				_str_set_array(TRUE, &groups_only_cli, optarg);
				break;
			case 's':
				if (!optarg) {
					g_printerr("Expected argument to the '-%c' option\n", c);
					exit(1);
				}
				g_strlcpy(syslog_id, optarg, sizeof(syslog_id));
				break;
			case 'v':
				logger_verbose_default();
				break;
			case 'q':
				flag_quiet = ~0;
				logger_init_level(GRID_LOGLVL_ERROR);
				break;
			default:
				if (!flag_quiet)
					g_printerr("Unexpected option : %c\n", c);
				exit(1);
		}
	}

	if (flag_help) {
		main_usage();
		exit(0);
		return;
	}

	/* check for additionnal arguments */
	if (optind >= argc) {
		main_usage();
		exit(1);
		return;
	}

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
	struct sockaddr_un sun;

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	g_strlcpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);

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

int
main(int argc, char ** args)
{
	guint proc_count;
	int rc = 1;
	struct event_base *libevents_handle = NULL;

	void postfork(void *udata) {
		(void) udata;
		if (libevents_handle)
			event_reinit(libevents_handle);
	}

	groups_only_cli = NULL;
	groups_only_cfg = NULL;
	bzero(pidfile_path, sizeof(pidfile_path));
	bzero(default_working_directory, sizeof(default_working_directory));

	g_strlcpy(sock_path, GRIDINIT_SOCK_PATH, sizeof(sock_path));

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

	if (-1 == servers_save_unix(sock_path)) {
		ERROR("Failed to open the UNIX socket for commands : %s",
			strerror(errno));
		goto label_exit;
	}

	/* Starts the network and the signal management */
	DEBUG("Initiating the network and signals management");
	libevents_handle = event_init();

	supervisor_set_callback_postfork(postfork, NULL);

	signals_manage(SIGTERM);
	signals_manage(SIGABRT);
	signals_manage(SIGINT);
	signals_manage(SIGALRM);
	signals_manage(SIGQUIT);
	signals_manage(SIGUSR1);
	signals_manage(SIGPIPE);
	signals_manage(SIGUSR2);
	signals_manage(SIGCHLD);
	if (!servers_monitor_all()) {
		ERROR("Failed to monitor the server sockets");
		goto label_exit;
	}

	timer_event_arm(TRUE);

	DEBUG("Starting the event loop!");

	/* start all the enabled processes */
	proc_count = supervisor_children_start_enabled(NULL, NULL);
	DEBUG("First started %u processes", proc_count);

	while (flag_running) {

		proc_count = supervisor_children_catharsis(NULL, alert_proc_died);
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

		if (!flag_running)
			break;
		if (flag_check_socket)
			servers_ensure();
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

		/* Be sure to wake */
		alarm(1);

		/* Manages the connections pool */
		if (0 > event_loop(EVLOOP_ONCE)) {
			ERROR("event_loop() error : %s", strerror(errno));
			break;
		}
	}

	rc = 0;

label_exit:
	/* stop all the processes */
	DEBUG("Stopping all the children");
	(void) supervisor_children_stopall(1);

	thread_ignore_signals();
	DEBUG("Waiting for them to die");
	while (supervisor_children_kill_disabled() > 0)
		sleep(1);

	/* clean the working structures */
	thread_ignore_signals();

	DEBUG("Cleaning the working structures");
	if (libevents_handle)
		event_base_free(libevents_handle);

	supervisor_children_cleanall();
	supervisor_children_fini();
	servers_clean();
	signals_clean();
	g_free(config_path);

	gridinit_alerting_close();
	closelog();
	return rc;
}

