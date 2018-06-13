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

#ifndef __GRIDINIT_ALERTS_H__
# define __GRIDINIT_ALERTS_H__
# include <glib.h>
# define GRIDINIT_EVENT_STARTED   1
# define GRIDINIT_EVENT_RESTARTED 2
# define GRIDINIT_EVENT_BROKEN    3

/**
 * @param udata the user data provided in the exported structure 
 */
typedef void (*gridinit_alert_handler_f) (void *udata, int event, const char *msg);

/**
 * @param udata the user data provided in the exported structure 
 */
typedef void (*gridinit_alert_init_f) (void *udata, GHashTable *params);

/**
 * @param udata the user data provided in the exported structure 
 */
typedef void (*gridinit_alert_fini_f) (void *udata);

/**
 * The type of structure that must be exported by the module
 * under the name MODULE_HANDLER_gridnit_alert;
 */
struct gridinit_alert_handle_s {
	void *module_data;
	gridinit_alert_init_f init;
	gridinit_alert_fini_f fini;
	gridinit_alert_handler_f send;
};

#endif
