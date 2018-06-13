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

#include <event.h>
#include <glib.h>
#include <gmodule.h>

#include <gridinit-utils.h>
#include "./gridinit_internals.h"
#include "./gridinit_alerts.h"

static GModule *module = NULL;
static struct gridinit_alert_handle_s *handle = NULL;

/* ------------------------------------------------------------------------- */

gboolean
gridinit_alerting_configure(const gchar *path, const gchar *symbol,
	GHashTable *ht_params, GError **err)
{
	TRACE("trying to configure the alerting with the module [%s] and the symbol [%s]",
		path, symbol);
	if (!symbol || !path) {
		if (err) {
			*err = g_error_printf(LOG_DOMAIN, 500, "Invalid parameter");
		}
		return FALSE;
	}
	if (module != NULL) {
		if (err) {
			*err = g_error_printf(LOG_DOMAIN, 500, "Module already loaded");
		}
		return FALSE;
	}

	/* Open the module and locate the exported symbol */
	if (NULL == (module = g_module_open (path, 0))) {
		if (err) {
			*err = g_error_printf(LOG_DOMAIN, 500,
				"Cannot load the plug-in from file %s (%s)",
				path, g_module_error());
		}
		return FALSE;
	}

	gpointer pointer = NULL;
	if (!g_module_symbol(module, symbol, &pointer) || !pointer) {
		if (err) {
			*err = g_error_printf(LOG_DOMAIN, 500,
				"Cannot get the exported structure (%s) from the plug-in %p (%s)",
				symbol, (void*)module, g_module_error());
		}
		return FALSE;
	}

	handle = pointer;
	if (handle->init) {
		handle->init(handle->module_data, ht_params);
	}

	return TRUE;
}


void
gridinit_alerting_send(int event, const char *msg)
{
	if (event == GRIDINIT_EVENT_BROKEN) {
		ERROR("Process alert: %s", msg);
	} else if (event == GRIDINIT_EVENT_RESTARTED) {
		WARN("Process alert: %s", msg);
	} else {
		NOTICE("Process alert: %s", msg);
	}

	if (!module || !handle || !handle->send)
		return;

	handle->send(handle->module_data, event, msg);
}

void
gridinit_alerting_close(void)
{
	if (handle && handle->fini)
		handle->fini(handle->module_data);
	if (module)
		g_module_close(module);

	module = NULL;
	handle = NULL;
}

