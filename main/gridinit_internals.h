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

#ifndef  __GRIDINIT_INTERNALS_H__
# define __GRIDINIT_INTERNALS_H__ 1

#ifndef  CFG_KEY_DELAY_KILL
# define CFG_KEY_DELAY_KILL "delay_sigkill"
#endif

# ifndef  GRIDINIT_SOCK_PATH
#  define GRIDINIT_SOCK_PATH "/var/run/gridinit.sock"
# endif

#ifndef  CFG_KEY_LISTEN
# define CFG_KEY_LISTEN "listen"
#endif

#ifndef  CFG_KEY_PATH_PIDFILE
# define CFG_KEY_PATH_PIDFILE "pidfile"
#endif

#ifndef  CFG_KEY_PATH_WORKINGDIR
# define CFG_KEY_PATH_WORKINGDIR "working_dir"
#endif

#ifndef  CFG_KEY_LIMIT_STACKSIZE
# define CFG_KEY_LIMIT_STACKSIZE "limit.stack_size"
#endif

#ifndef  CFG_KEY_LIMIT_CORESIZE
# define CFG_KEY_LIMIT_CORESIZE "limit.core_size"
#endif

#ifndef  CFG_KEY_LIMIT_NBFILES
# define CFG_KEY_LIMIT_NBFILES "limit.max_files"
#endif

#ifndef  CFG_KEY_GID
# define CFG_KEY_GID "gid"
#endif

#ifndef  CFG_KEY_GROUP
# define CFG_KEY_GROUP "group"
#endif

#ifndef  CFG_KEY_UID
# define CFG_KEY_UID "uid"
#endif

#ifndef  CFG_KEY_USER
# define CFG_KEY_USER "user"
#endif

#ifndef  CFG_KEY_INCLUDES
# define CFG_KEY_INCLUDES "include"
#endif

#ifndef  CFG_KEY_GROUPSONLY
# define CFG_KEY_GROUPSONLY "groups_only"
#endif

#ifndef  CFG_KEY_INHERIT
# define CFG_KEY_INHERIT "inherit_env"
#endif

#define BOOL(i) ((i)!=0)

gboolean gridinit_group_in_set(const gchar *group, const gchar *set);

#endif
