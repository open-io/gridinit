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

#ifndef __FORMAT_OUTPUT__
#define __FORMAT_OUTPUT__

# include <glib.h>

int format_to_int(gchar *format);
void print_as_json(gchar *status, gchar *start, char *error, gboolean first);
void print_as_yaml(gchar *status, gchar *start, char *error, gboolean first);
void print_as_csv(gchar *status, gchar *start, char *error);
void print_header(gchar *format);
void print_footer(gchar *format);
void print_body(gchar *format, gchar *status, gchar *start, gchar *error, gboolean first);
void print_status_header(gchar *format);
void status_body_json(gchar *fmt_line, int size);
void status_body_yaml(gchar *fmt_line, int size);
void status_body_csv(gchar *fmt_line, int size);
void print_status_sep(gchar *format, int count);
void get_line_format(gchar *format, gchar *fmt_line, int size);

#endif
