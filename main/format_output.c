/*
Copyright (C) 2015 OpenIO SAS, as part of OpenIO SDS

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

#include <stdio.h>
#include <glib.h>
#include "./format_output.h"

int
format_to_int(gchar *format)
{
	if (g_strcmp0(format, "json") == 0)
		return 0;
	if (g_strcmp0(format, "csv") == 0)
		return 1;
	if (g_strcmp0(format, "yaml") == 0)
		return 2;
	else
		return -1;
}

void
print_as_json(gchar *status, gchar *start, gchar *error, gboolean first)
{
	gchar header[] = "  {\n";
	gchar footer[] = "  }";
	gchar tab[] = "    ";

	if(!first)
		fprintf(stdout, ",\n");

	fprintf(stdout, "%s", header);
	fprintf(stdout, "%s\"status\": \"%s\",\n", tab, status);
	fprintf(stdout, "%s\"start\": \"%s\",\n", tab, start);
	fprintf(stdout, "%s\"error\": \"%s\"\n", tab, error);
	fprintf(stdout, "%s", footer);
}

void
print_as_yaml(gchar *status, gchar *start, gchar *error, gboolean first)
{
	gchar header[] = "  {\n";
	gchar footer[] = "  }";
	gchar tab[] = "    ";

	if(!first)
		fprintf(stdout, ",\n");

	fprintf(stdout, "%s", header);
	fprintf(stdout, "%sstatus: %s,\n", tab, status);
	fprintf(stdout, "%sstart: %s,\n", tab, start);
	fprintf(stdout, "%serror: %s\n", tab, error);
	fprintf(stdout, "%s", footer);
}



void
print_as_csv(gchar *status, gchar *start, gchar *error)
{
	fprintf(stdout, "%s,%s,%s\n", status, start, error);
}


void
print_header(gchar *format)
{
	switch (format_to_int(format)) {
		case 0:
		case 2:
			fprintf(stdout, "[\n");
			break;
		case 1:
			fprintf(stdout, "status,start,error\n");
			break;
		default:
			break;
	}
}

void
print_footer(gchar *format)
{
	switch (format_to_int(format)) {
		case 0 :
		case 2:
			fprintf(stdout, "\n]\n");
			break;
		default:
			break;
	}
	return;
}

void
print_body(gchar *format, gchar *status, gchar *start, gchar *error, gboolean first){
	switch (format_to_int(format)) {
		case 0:
			print_as_json(status, start, error, first);
			break;
		case 1:
			print_as_csv(status, start, error);
			break;
		case 2:
			print_as_yaml(status, start, error, first);
			break;
		default:
			fprintf(stdout, "%s\t%s\t%s\n", status, start, error);
	}
}

void
print_status_header(gchar *format)
{
	switch (format_to_int(format)) {
		case 0:
		case 2:
			fprintf(stdout, "[\n");
			break;
		case 1:
			fprintf(stdout,
				"key,status,pid,#start,#died,csz,ssz,mfd,since,group,cmd\n");
			break;
		default:
			break;
	}
}

void
status_body_json(gchar *fmt_line, int size)
{
	g_snprintf(fmt_line, size,
			"  {\n    \"key\":\"%%s\",\n    \"status\":\"%%s\","
			"\n    \"pid\":\"%%d\",\n    \"#start\":\"%%d\","
			"\n    \"#died\":\"%%d\",\n    \"csz\":\"%%ld\","
			"\n    \"ssz\":\"%%ld\",\n    \"mfd\":\"%%ld\","
			"\n    \"since\":\"%%s\",\n    \"group\":\"%%s\","
			"\n    \"cmd\":\"%%s\"\n  }");
}


void
status_body_yaml(gchar *fmt_line, int size)
{
	g_snprintf(fmt_line, size,
			"  {\n    key: %%s,\n    status: %%s,"
			"\n    pid: %%d,\n    #start: %%d,"
			"\n    #died: %%d,\n    csz: %%ld,"
			"\n    ssz: %%ld,\n    mfd: %%ld,"
			"\n    since: %%s,\n    group: %%s,"
			"\n    cmd: %%s\n  }");
}

void
status_body_csv(gchar *fmt_line, int size)
{
	g_snprintf(fmt_line, size,
			"%%s,%%s,%%d,%%d,%%d,%%ld,%%ld,%%ld,%%s,%%s,%%s\n");
}

void
print_status_sep(gchar *format, int count)
{
	switch (format_to_int(format)) {
		case 0:
		case 2:
			if(count)
				fprintf(stdout, ",\n");
		default:
			break;
	}
}

void
get_line_format(gchar *format, gchar *fmt_line, int size)
{
	switch (format_to_int(format)) {
		case 0:
			status_body_json(fmt_line, size);
			break;
		case 1:
			status_body_csv(fmt_line, size);
			break;
		case 2:
			status_body_yaml(fmt_line, size);
			break;
		default:
			break;
	}
}
