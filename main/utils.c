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

#include <glib.h>

#include "./gridinit_internals.h"

#define STR_SKIP_SPACES(s) do {\
	register gchar c;\
	for (; (c = *s) && g_ascii_isspace(c) ;++s);\
} while (0)

#define STR_TRIM_TRAILING_SPACES(s) do { \
	register gchar c, *end; \
	for (end = s; *end ;++end); \
	-- end; \
	for (; end > s && (c = *end) && g_ascii_isspace(c) ;--end) *end = '\0'; \
} while (0)

gboolean
gridinit_group_in_set(const gchar *group, const gchar *set)
{
	gchar **tokens, **token, *g;

	tokens = g_strsplit_set(set, ",", -1);
	if (!tokens)
		return 0;
	for (token=tokens; (g = *token) ;token++) {
		STR_SKIP_SPACES(g);
		STR_TRIM_TRAILING_SPACES(g);
		if (!*g)
			continue;
		if (0 == g_ascii_strcasecmp(g, group)) {
			g_strfreev(tokens);
			return TRUE;
		}
	}
	g_strfreev(tokens);
	return FALSE;
}

