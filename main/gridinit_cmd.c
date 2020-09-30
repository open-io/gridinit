/*
gridinit, a monitor for non-daemon processes.
Copyright (C) 2013 AtoS Worldline, original work aside of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS

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
#include <getopt.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include "./gridinit_internals.h"

#define UNUSED __attribute__ ((unused))

#define MINI 0
#define MEDIUM 1


static gchar *sock_path = NULL;
static gchar line[8192] = "";
static gboolean flag_color = FALSE;
static gchar *format = NULL;
static gboolean flag_version = FALSE;
#define BOOL(i) (i?1:0)

struct dump_as_is_arg_s {
	guint count_success;
	guint count_errors;
};

struct child_info_s {
	char *key;
	char *group;
	char *cmd;
	gint pid;
	guint uid;
	guint gid;
	gboolean enabled;
	gboolean respawn;
	gboolean broken;
	gboolean breakable;
	guint32 user_flags;
	time_t last_start_attempt;
	guint counter_started;
	guint counter_died;
	struct {
		long core_size;
		long stack_size;
		long nb_files;
	} rlimits;
};

static void child_info_free(struct child_info_s *ci) {
	if (ci->key) g_free(ci->key);
	if (ci->cmd) g_free(ci->cmd);
	if (ci->group) g_free(ci->group);
	g_free(ci);
}

struct keyword_set_s {
	const gchar *already;
	const gchar *done;
	const gchar *failed;

	const gchar *broken;
	const gchar *down;
	const gchar *disabled;
	const gchar *up;
};

static struct keyword_set_s KEYWORDS_SHORT = {
	"ALREADY",
	"DONE",
	"FAILED",
	"BROKEN",
	"DOWN",
	"DISABLED",
	"UP"
};

static struct keyword_set_s KEYWORDS_NORMAL = {
	"ALREADY ",
	"DONE    ",
	"FAILED  ",
	"BROKEN  ",
	"DOWN    ",
	"DISABLED",
	"UP      "
};

static struct keyword_set_s KEYWORDS_COLOR = {
	"[33mALREADY[0m ",
	"[32mDONE[0m    ",
	"[31mFAILED[0m  ",
	"[31mBROKEN[0m  ",
	"[33mDOWN[0m    ",
	"[36mDISABLED[0m",
	"[32mUP[0m      "
};

static GOptionEntry entries[] = {
	{"color", 'c', 0, G_OPTION_ARG_NONE, &flag_color,
	 "coloured display ", NULL},
	{"sock-path", 'S', 0, G_OPTION_ARG_FILENAME, &sock_path,
	 "explicit unix socket path", "SOCKET"},
	{"format", 'f', 0, G_OPTION_ARG_STRING, &format,
	 "output result by given FORMAT. Available FORMAT value are "
	 "csv or json","FORMAT"},
	{"version", 'v', 0, G_OPTION_ARG_NONE, &flag_version,
	 "Display the version of gridinit_cmd", NULL},
	{NULL}
};

static const gchar options[] = "(status{,2,3}|start|stop|reload|repair) [ID...]";

static const gchar description[] =
	"\n COMMANDS:\n"
	"  status* : Displays the status of the given processes or groups\n"
	"  start   : Starts the given processes or groups, even if broken\n"
	"  kill    : Stops the given processes or groups, they won't be automatically\n"
	"            restarted even after a configuration reload\n"
	"  stop    : Calls 'kill' until the children exit\n"
	"  restart : Restarts the given processes or groups\n"
	"  reload  : Reloads the configuration, stopping obsolete processes, starting\n"
	"            the newly discovered. Broken or stopped processes are not restarted\n"
	"  repair  : Removes the broken flag set on a process. Start must be called to\n"
	"            restart the process.\n"
	"with ID the key of a process, or '@GROUP', with GROUP the name of a process\n"
	"group\n";

typedef enum FORMAT FORMAT;

enum FORMAT {DEFAULT = 0, CSV = 1, JSON = 2};

static FORMAT
parse_format(const gchar *cfg_format)
{
	if (g_strcmp0(cfg_format, "json") == 0)
		return JSON;
	if (g_strcmp0(cfg_format, "csv") == 0)
		return CSV;
	else
		return DEFAULT;
}


static int
__open_unix_client(const char *path)
{
	struct sockaddr_un local = {0};

	if (!path || strlen(path) >= sizeof(local.sun_path)) {
		errno = EINVAL;
		return -1;
	}
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, path, sizeof(local.sun_path));

	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (-1 == connect(sock, (struct sockaddr *)&local, sizeof(local))) {
		int errsav = errno;
		close(sock);
		errno = errsav;
		return -1;
	}

	errno = 0;
	return sock;
}

static gint
compare_child_info(gconstpointer p1, gconstpointer p2)
{
	const struct child_info_s *c1, *c2;
	c1 = p1;
	c2 = p2;
	return g_ascii_strcasecmp(c1->key, c2->key);
}

static const char *
get_child_status(struct child_info_s *ci, struct keyword_set_s *kw)
{
	if (ci->broken)
		return kw->broken;
	if (!ci->enabled)
		return kw->disabled;
	if (ci->pid <= 0)
		return kw->down;
	return kw->up;
}

static size_t
get_longest_group(GList *all_jobs)
{
	size_t maxlen = 5;
	for (GList *l=all_jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		size_t len = strlen(ci->group);
		if (len > maxlen)
			maxlen = len;
	}
	return maxlen;
}

static size_t
get_longest_key(GList *all_jobs)
{
	size_t maxlen = 4;
	for (GList *l=all_jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		size_t len = strlen(ci->key);
		if (len > maxlen)
			maxlen = len;
	}
	return maxlen;
}

static void
unpack_line(gchar *str, gchar **start, int *code)
{
	*start = str;
	*code = EINVAL;
	if (!str)
		return ;
	str = g_strstrip(str);
	gchar *p = NULL;
	*code = g_ascii_strtoll(str, &p, 10);
	if (p)
		*start = g_strchug(p);
}

static GList*
read_services_list(FILE *in_stream)
{
	GList *all_jobs = NULL;

	while (!feof(in_stream) && !ferror(in_stream)) {
		if (NULL != fgets(line, sizeof(line), in_stream)) {
			gchar *l = g_strstrip(line);
			gchar **tokens = g_strsplit_set(l, " \t\r\n", 15);
			if (tokens) {
				if (g_strv_length(tokens) == 15) {
					struct child_info_s ci;
					ci.pid = atoi(tokens[0]);
					ci.enabled = BOOL(atoi(tokens[1]));
					ci.broken = BOOL(atoi(tokens[2]));
					ci.respawn = BOOL(atoi(tokens[3]));
					ci.counter_started = atoi(tokens[4]);
					ci.counter_died = atoi(tokens[5]);
					ci.last_start_attempt = atol(tokens[6]);
					ci.rlimits.core_size = atol(tokens[7]);
					ci.rlimits.stack_size = atol(tokens[8]);
					ci.rlimits.nb_files = atol(tokens[9]);
					ci.uid = atol(tokens[10]);
					ci.gid = atol(tokens[11]);
					ci.key = g_strdup(tokens[12]);
					ci.group = g_strdup(tokens[13]);
					ci.cmd = g_strdup(tokens[14]);
					all_jobs = g_list_prepend(all_jobs,
						g_memdup(&ci, sizeof(struct child_info_s)));
				}
				g_strfreev(tokens);
			}
		}
	}

	return g_list_sort(all_jobs, compare_child_info);
}

static const gchar json_basic_translations[] =
{
	  0,   0,   0,   0,   0,   0,   0,   0,
	'b', 't', 'n',   0, 'f', 'r',   0,   0,
};

static gchar * str_to_json_str(const char *s0) {
	GString *json_str = g_string_new("");
	int len = strlen(s0);
	for (const char *s = s0; (len < 0 && *s) || (s - s0) < len ;) {
		if (*s & (const char)0x80) {  // (part of a) unicode character
			gunichar c = g_utf8_get_char_validated(s, -1);
			if (c == (gunichar)-1) {
				// something wrong happened, let the client deal with it
				g_string_append_c(json_str, *(s++));
			} else if (c == (gunichar)-2) {
				// middle of a unicode character
				char *end = g_utf8_next_char(s);
				while (s < end && *s)
					g_string_append_c(json_str, *(s++));
			} else {
				g_string_append_unichar(json_str, c);
				s = g_utf8_next_char(s);
			}
		} else if (*s < ' ') {  // control character
			g_string_append_c(json_str, '\\');
			switch (*s) {
			case '\b':
			case '\t':
			case '\n':
			case '\f':
			case '\r':
				g_string_append_c(json_str, json_basic_translations[(int)*(s++)]);
				break;
			default:
				g_string_append_printf(json_str, "u%04x", *(s++));
				break;
			}
		} else {  // printable ASCII character
			switch (*s) {
			case '"':
			case '\\':
			case '/':
				g_string_append_c(json_str, '\\');
				/* FALLTHROUGH */
			default:
				g_string_append_c(json_str, *(s++));
				break;
			}
		}
	}
	return g_string_free(json_str, FALSE);
}

static void
dump_as_is(FILE *in_stream, void *udata)
{
	gboolean first = TRUE;
	struct dump_as_is_arg_s *dump_args = udata;

	FORMAT format_t = parse_format(format);

	struct keyword_set_s *kw;
	if (format_t != DEFAULT)
		kw = &KEYWORDS_SHORT;
	else if (flag_color)
		kw = &KEYWORDS_COLOR;
	else
		kw = &KEYWORDS_NORMAL;

	/* Prin tthe title */
	switch (format_t) {
		case JSON:
			fputs("[", stdout);
			break;
		case CSV:
			fputs("status,start,error\n", stdout);
			/* FALLTHROUGH */
		default:
			break;
	}

	/* Print the lines */
	while (!feof(in_stream) && !ferror(in_stream)) {
		bzero(line, sizeof(line));
		if (NULL != fgets(line, sizeof(line), in_stream)) {
			int code = 0;
			gchar *start = NULL;
			unpack_line(line, &start, &code);

			if (dump_args) {
				if (code==0 || code==EALREADY)
					dump_args->count_success ++;
				else
					dump_args->count_errors ++;
			}
			gchar *status = (gchar *) (code==0 ? kw->done :
					(code==EALREADY?kw->already:kw->failed));
			const char *error = strerror(code);

			switch (format_t) {
				case JSON:
					if(!first)
						fprintf(stdout, ",\n");
					gchar *json_str_status = str_to_json_str(status);
					gchar *json_str_start = str_to_json_str(start);
					gchar *json_str_error = str_to_json_str(error);
					fprintf(stdout, "{\"status\": \"%s\",\"start\": \"%s\",\"error\": \"%s\"}\n",
						json_str_status, json_str_start, json_str_error);
					g_free(json_str_status);
					g_free(json_str_start);
					g_free(json_str_error);
					break;
				case CSV:
					fprintf(stdout, "%s,%s,%s\n", status, start, error);
					break;
				default:
					fprintf(stdout, "%s\t%s\t%s\n", status, start, error);
			}
			first = FALSE;
		}
	}

	if (format_t == JSON)
		fputs("]", stdout);
	fflush(stdout);
}

static FILE*
open_cnx(void)
{
	int req_fd = -1;
	if (-1 == (req_fd = __open_unix_client(sock_path))) {
		g_printerr("Connection to UNIX socket [%s] failed : %s\n", sock_path, strerror(errno));
		return NULL;
	}

	FILE *req_stream = NULL;
	if (NULL == (req_stream = fdopen(req_fd, "a+"))) {
		g_printerr("Connection to UNIX socket [%s] failed : %s\n", sock_path, strerror(errno));
		close(req_fd);
		return NULL;
	}

	return req_stream;
}

static int
send_commandv(void (*dumper)(FILE *, void*), void *udata, const char *cmd, int argc, char **args)
{
	FILE *req_stream = open_cnx();
	if (!req_stream)
		return 1;

	fputs(cmd, req_stream);
	fputc(' ', req_stream);
	for (int i=0; i<argc ;i++) {
		fputs(args[i], req_stream);
		fputc(' ', req_stream);
	}
	fputc('\n', req_stream);

	fflush(req_stream);
	dumper(req_stream, udata);
	fclose(req_stream);
	return 0;
}

static void
_on_reply(FILE *in_stream, void *u)
{
	GList **out = u;
	g_assert_nonnull(out);
	*out = read_services_list(in_stream);
}

static int
_fetch_services(GList **out)
{
	GList *jobs = NULL;

	int rc = send_commandv(_on_reply, &jobs, "status", 0, (char*[]){NULL});
	if (rc != 0) {
		g_list_free_full(jobs, (GDestroyNotify)child_info_free);
		*out = NULL;
		return 1;
	} else {
		*out = jobs;
		return 0;
	}
}

static GList *
_filter_services(GList *original, char **filters, int *counters)
{
	gboolean matches(struct child_info_s *ci) {
		for (int i=0; filters[i] ;i++) {
			const char *pattern = filters[i];
			if (pattern[0]=='@') {
				if (gridinit_group_in_set(pattern+1, ci->group)) {
					if (counters) counters[i] ++;
					return TRUE;
				}
			} else {
				if (!g_ascii_strcasecmp(ci->key, pattern)) {
					if (counters) counters[i] ++;
					return TRUE;
				}
			}
		}
		return FALSE;
	}

	GList *result = NULL;
	for (GList *l = original; l ;l = l->next) {
		if (!filters[0] || matches(l->data)) {
			result = g_list_append(result, l->data);
		}
	}
	return result;
}

static int
command_status(int lvl, int argc, char **args)
{
	char fmt_line[256];

	int *counters = alloca(sizeof(int) * (argc+1));
	memset(counters, 0, sizeof(int) * (argc+1));

	GList *all_jobs = NULL;
	if (0 != _fetch_services(&all_jobs))
		return 1;

	GList *jobs = _filter_services(all_jobs, args, counters);
	FORMAT format_t = parse_format(format);

	/* Print the header and compute the format for each line */
	if (format_t == DEFAULT) {
		const size_t maxkey = get_longest_key(jobs);
		const size_t maxgroup = get_longest_group(jobs);
		char fmt_title[256];
		switch (lvl) {
			case 0:
				g_snprintf(fmt_title, sizeof(fmt_title),
						"%%-%us %%-8s %%6s %%s\n",
						(guint)maxkey);
				g_snprintf(fmt_line, sizeof(fmt_line),
						"%%-%us %%s %%6d %%s\n",
						(guint)maxkey);
				fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "GROUP");
				break;
			case 1:
				g_snprintf(fmt_title, sizeof(fmt_title),
						"%%-%us %%-8s %%5s %%6s %%5s %%19s %%%us %%s\n",
						(guint)maxkey, (guint)maxgroup);
				g_snprintf(fmt_line, sizeof(fmt_line),
						"%%-%us %%s %%5d %%6d %%5d %%19s %%%us %%s\n",
						(guint)maxkey, (guint)maxgroup);
				fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "#START",
						"#DIED", "SINCE", "GROUP", "CMD");
				break;
			default:
				g_snprintf(fmt_title, sizeof(fmt_title),
						"%%-%us %%-8s %%5s %%6s %%5s %%8s %%8s %%8s %%19s %%%us %%s\n",
						(guint)maxkey, (guint)maxgroup);
				g_snprintf(fmt_line, sizeof(fmt_line),
						"%%-%us %%s %%5d %%6d %%5d %%8ld %%8ld %%8ld %%19s %%%us %%s\n",
						(guint)maxkey, (guint)maxgroup);

				fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "#START",
						"#DIED", "CSZ", "SSZ", "MFD", "SINCE", "GROUP", "CMD");
				break;
		}
	} else if (format_t == CSV) {
		g_snprintf(fmt_line, sizeof(fmt_line),
				"%%s,%%s,%%d,%%d,%%d,%%ld,%%ld,%%ld,%%s,%%s,%%s\n");
		/* Print the title */
		fputs("key,status,pid,#start,#died,csz,ssz,mfd,since,group,cmd\n", stdout);
	} else if (format_t == JSON) {
		g_snprintf(fmt_line, sizeof(fmt_line),
				"{\"key\":\"%%s\",\"status\":\"%%s\",\"pid\":%%d,"
				"\"#start\":%%d,\"#died\":%%d,\"csz\":%%ld,\"ssz\":%%ld,\"mfd\":%%ld,"
				"\"since\":\"%%s\",\"group\":\"%%s\","
				"\"cmd\":\"%%s\"}\n");
		/* Print the opening of the object */
		fputs("[", stdout);
	}

	int count_misses = 0, count_broken = 0, count_down = 0, count_all = 0;

	struct keyword_set_s *kw;
	if (format_t != DEFAULT)
		kw = &KEYWORDS_SHORT;
	else if (flag_color)
		kw = &KEYWORDS_COLOR;
	else
		kw = &KEYWORDS_NORMAL;

	/* iterate on the lines */
	for (GList *l=jobs; l ;l=l->next) {
		char str_time[20] = "---------- --------";
		const char * str_status = "-";
		struct child_info_s *ci = ci = l->data;

		/* Prepare some fields */
		strftime(str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S",
				gmtime(&(ci->last_start_attempt)));
		str_status = get_child_status(ci, kw);

		/* Manage counters */
		if (str_status == kw->down)
			count_down ++;
		if (str_status == kw->broken)
			count_broken ++;
		count_all ++;

		/* Print now! */
		if (format_t != DEFAULT) {
			if (format_t == JSON && count_all > 1)
				fputs(",", stdout);

			gchar *json_str_key = NULL;
			gchar *json_str_status = NULL;
			gchar *json_str_time = NULL;
			gchar *json_str_group = NULL;
			gchar *json_str_cmd = NULL;
			if (format_t == JSON) {
				json_str_key = str_to_json_str(ci->key);
				json_str_status = str_to_json_str(str_status);
				json_str_time = str_to_json_str(str_time);
				json_str_group = str_to_json_str(ci->group);
				json_str_cmd = str_to_json_str(ci->cmd);
			}

			fprintf(stdout, fmt_line, json_str_key?:ci->key,
				json_str_status?:str_status, ci->pid, ci->counter_started,
				ci->counter_died, ci->rlimits.core_size, ci->rlimits.stack_size,
				ci->rlimits.nb_files, json_str_time?:str_time,
				json_str_group?:ci->group, json_str_cmd?:ci->cmd);

			g_free(json_str_key);
			g_free(json_str_status);
			g_free(json_str_time);
			g_free(json_str_group);
			g_free(json_str_cmd);
		} else {
			switch (lvl) {
				case 0:
					fprintf(stdout, fmt_line, ci->key, str_status, ci->pid, ci->group);
					break;
				case 1:
					fprintf(stdout, fmt_line,
							ci->key, str_status, ci->pid,
							ci->counter_started, ci->counter_died,
							str_time, ci->group, ci->cmd);
					break;
				default:
					fprintf(stdout, fmt_line,
							ci->key, str_status, ci->pid,
							ci->counter_started, ci->counter_died,
							ci->rlimits.core_size, ci->rlimits.stack_size, ci->rlimits.nb_files,
							str_time, ci->group, ci->cmd);
					break;
			}
		}
	}
	g_list_free_full(all_jobs, (GDestroyNotify)child_info_free);
	g_list_free(jobs);

	if (format_t == JSON)
		fputs("]", stdout);
	fflush(stdout);

	/* If patterns have been specified, we must find items (the user
	 * expects something to show up */
	for (int i=0; i<argc ;i++) {
		if (!counters[i])
			count_misses ++;
	}
	return (count_down ? 1 : 0) | (count_misses ? 2 : 0) | (count_broken ? 4 : 0);
}


static int
command_status0(int argc, char **args)
{
	return command_status(0, argc, args);
}

static int
command_status1(int argc, char **args)
{
	return command_status(1, argc, args);
}

static int
command_status2(int argc, char **args)
{
	return command_status(2, argc, args);
}

static int
command_start(int argc, char **args)
{
	struct dump_as_is_arg_s dump_args = {};

	int rc = send_commandv(dump_as_is, &dump_args, "start", argc, args);
	return rc
		|| dump_args.count_errors != 0
		|| dump_args.count_success == 0;
}

static int
command_kill(int argc, char **args)
{
	struct dump_as_is_arg_s dump_args = {};

	int rc = send_commandv(dump_as_is, &dump_args, "stop", argc, args);
	return rc
		|| dump_args.count_errors != 0
		|| dump_args.count_success == 0;
}

static gboolean
_all_down(char **args, gboolean *down)
{
	GList *all_jobs = NULL;
	if (0 != _fetch_services(&all_jobs))
		return FALSE;

	GList *jobs = _filter_services(all_jobs, args, NULL);
	for (GList *l = jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		if (ci->pid > 0)
			*down = FALSE;
	}
	g_list_free_full(all_jobs, (GDestroyNotify)child_info_free);
	g_list_free(jobs);
	return TRUE;
}

static int
command_stop(int argc, char **args)
{
	FORMAT format_t = parse_format(format);
	for (;;) {
		gboolean d = TRUE;
		if (!_all_down(args, &d))
			return 1;
		if (d)
			return 0;
		/* If standart output format*/
		if (format_t != DEFAULT)
			g_print("# Stopping...\n");
		if (0 != command_kill(argc, args))
			return 1;
		g_usleep(G_TIME_SPAN_SECOND);
	}
	return 0;
}

static int
command_restart(int argc, char **args)
{
	struct dump_as_is_arg_s dump_args = {};

	int rc = send_commandv(dump_as_is, &dump_args, "restart", argc, args);
	return rc
		|| dump_args.count_errors != 0
		|| dump_args.count_success == 0;
}

static int
command_repair(int argc, char **args)
{
	struct dump_as_is_arg_s dump_args = {};

	int rc = send_commandv(dump_as_is, &dump_args, "repair", argc, args);
	return rc
		|| dump_args.count_errors != 0
		|| dump_args.count_success == 0;
}

static int
command_reload(int argc UNUSED, char **args UNUSED)
{
	struct dump_as_is_arg_s dump_args = {};

	int rc = send_commandv(dump_as_is, &dump_args, "reload", 0, (char*[]){NULL});
	return rc
		|| dump_args.count_errors != 0
		|| dump_args.count_success == 0;
}


/* ------------------------------------------------------------------------- */

struct command_s {
	const gchar *name;
	int (*action) (int argc, char **args);
} COMMANDS[] = {
	{ "status",  command_status0 },
	{ "status2", command_status1 },
	{ "status3", command_status2 },
	{ "start",   command_start },
	{ "stop",    command_stop },
	{ "kill",    command_kill },
	{ "restart", command_restart },
	{ "reload",  command_reload },
	{ "repair",  command_repair },
	{ NULL, NULL }
};

static void
usage(void)
{
	GOptionContext *context = g_option_context_new(options);
	g_option_context_add_main_entries(context, entries, NULL);
	g_option_context_set_summary(context, description);
	gchar *str_usage = g_option_context_get_help (context, TRUE, NULL);
	g_printerr("%s", str_usage);
	g_free(str_usage);
}

static gboolean
main_options(int *argc, char ***args)
{
	sock_path = g_strdup(GRIDINIT_SOCK_PATH);

	GError *error = NULL;
	GOptionContext *context = g_option_context_new(options);
	g_option_context_add_main_entries(context, entries, NULL);
	g_option_context_set_summary(context, description);
	return g_option_context_parse(context, argc, args, &error);
}


int
main(int argc, char ** args)
{
	close(0);

	if (!main_options(&argc, &args)) {
		usage();
		return 1;
	}

	if (flag_version) {
		fprintf(stdout, "gridinit_cmd version: %s\n", API_VERSION);
		return 0;
	}

	int opt_index = 1;
	if (!args[opt_index]) {
		usage();
		return 2;
	}

	for (struct command_s *cmd=COMMANDS; cmd->name ;cmd++) {
		if (0 == g_ascii_strcasecmp(cmd->name, args[opt_index]))
			return cmd->action(argc-(opt_index+1), args+(opt_index+1));
	}

	usage();
	return 1;
}
