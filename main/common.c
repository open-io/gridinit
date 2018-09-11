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

#include <sys/types.h>
#include <unistd.h>

#include "./gridinit-utils.h"

GError*
g_error_printf(const char *dom, int code, const char *fmt, ...)
{
	GError *e;
	gchar *str;
	va_list va;

	va_start(va, fmt);
	str = g_strdup_vprintf (fmt, va);
	va_end(va);

	e = g_error_new(g_quark_from_static_string(dom), code, "%s", str);
	g_free(str);
	return e;
}

