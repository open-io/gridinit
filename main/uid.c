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

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "./gridinit-utils.h"

static volatile uid_t effective_uid = 0;
static volatile uid_t effective_gid = 0;

static volatile uid_t real_uid = 0;
static volatile uid_t real_gid = 0;

gboolean
supervisor_rights_init(const char *user_name, const char *group_name, GError ** error)
{
	struct passwd *pwd = NULL;
	struct group *grp = NULL;

	pwd = getpwnam(user_name);
	if (pwd == NULL) {
		*error = g_error_new(gq_log, errno, "User [%s] not found in /etc/passwd", user_name);
		return FALSE;
	}

	grp = getgrnam(group_name);
	if (grp == NULL) {
		*error = g_error_new(gq_log, errno, "Group [%s] not found in /etc/group", group_name);
		return FALSE;
	}

	effective_gid = grp->gr_gid;
	effective_uid = pwd->pw_uid;
	NOTICE("rights_init : effective id set to %d:%d", effective_uid, effective_gid);

	real_gid = getuid();
	real_uid = getgid();
	NOTICE("rights_init : real id saved (%d:%d)", real_uid, real_gid);

	return TRUE;
}

int
supervisor_rights_gain(void)
{
	int status;

#ifdef _POSIX_SAVED_IDS
	status = seteuid(real_uid);
#else
	status = setreuid(-1, real_uid);
#endif
	return status;
}

int
supervisor_rights_lose(void)
{
	int status;

#ifdef _POSIX_SAVED_IDS
	status = seteuid(effective_uid);
#else
	status = setreuid(-1, effective_uid);
#endif
	return status;
}

