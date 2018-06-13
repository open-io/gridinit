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
#include <stdint.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>

#include "./gridinit-utils.h"

static const char*
get_rlimit_name(enum supervisor_limit_e what)
{
	switch (what) {
	case SUPERV_LIMIT_THREAD_STACK: return "RLIMIT_STACK";
	case SUPERV_LIMIT_MAX_FILES: return "RLIMIT_NOFILE";
	case SUPERV_LIMIT_CORE_SIZE: return "RLIMIT_CORE";
	}
	return "INVALID";
}

static int
get_rlimit_id(enum supervisor_limit_e what)
{
	switch (what) {
	case SUPERV_LIMIT_THREAD_STACK: return RLIMIT_STACK;
	case SUPERV_LIMIT_MAX_FILES: return RLIMIT_NOFILE;
	case SUPERV_LIMIT_CORE_SIZE: return RLIMIT_CORE;
	}
	
	errno = EINVAL;
	return -1;
}

static int
my_setrlimit(int res_id, struct rlimit *rl)
{
	int rc;
	typeof(errno) errsav;

	supervisor_rights_gain();
	errno = 0;
	rc = setrlimit(res_id, rl);
	errsav = errno;

	supervisor_rights_lose();
	errno = errsav;

	return rc;
}

static rlim_t
get_rlim_from_i64(gint64 i64)
{
	rlim_t res;

	if (i64 >= G_MAXLONG)
		return RLIM_INFINITY;
	if (i64 < 0)
		return -1;

	res = i64;
	return res;
}

static gint64
get_i64_from_rlim(rlim_t l)
{
	gint64 i64;

	if (l == RLIM_INFINITY)
		return G_MAXINT64;
#if 0
	if (l < 0)
		return -1;
#endif
	i64 = l;
	return i64;
}


int
supervisor_limit_set(enum supervisor_limit_e what, gint64 value)
{
	struct rlimit rl, rl_old;
	rlim_t _val;
	int res_id;

	_val = get_rlim_from_i64(value);
	res_id = get_rlimit_id(what);

	/* Try with the raw value */
	rl.rlim_cur = _val;
	rl.rlim_max = _val;
	if (0 == my_setrlimit(res_id, &rl))
		return 0;
	if (errno != EPERM) {
		WARN("supervisor_limit_set(%s,%"G_GINT64_FORMAT") error : %s",
				get_rlimit_name(what), value, strerror(errno));
		return -1;
	}
				
	/* The process has no special privileges, set the maximum available */
	if (-1 == getrlimit(res_id, &rl_old)) {
		WARN("supervisor_limit_get(%s,%"G_GINT64_FORMAT") error : %s",
				get_rlimit_name(what), value, strerror(errno));
		return -1;
	}

	rl.rlim_cur = rl_old.rlim_max;
	rl.rlim_max = rl_old.rlim_max;
	if (0 == my_setrlimit(res_id, &rl))
		return 0;
				
	WARN("supervisor_limit_set(%s,%"G_GINT64_FORMAT") error : %s",
			get_rlimit_name(what), value, strerror(errno));
	return -1;
}

int
supervisor_limit_get(enum supervisor_limit_e what, gint64 *value)
{
	struct rlimit rl;
	int res_id;

	if (!value) {
		errno = EINVAL;
		return -1;
	}

	res_id = get_rlimit_id(what);
	if (-1 == getrlimit(res_id, &rl))
		return -1;

	*value = get_i64_from_rlim(rl.rlim_cur);
	return 0;
}

