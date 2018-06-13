/*
gridinit, a monitor for non-daemon processes.
Copyright (C) 2013 AtoS Worldline, original work aside of Redcurrant
Copyright (C) 2015 OpenIO, modified for OpenIO Software Defined Storage

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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <glib.h>

#include "./gridinit_internals.h"
#include "../lib/gridinit-utils.h"

static volatile int backlog_unix = 65536;
static volatile int backlog_tcp = 4096;

static int
__addr_split(gchar *url_wrk, gchar ** host, gchar ** port)
{
	int len;
	gchar *last_semicolon;

	len = strlen(url_wrk);

	if (*url_wrk == '[') {	/*[IP]:PORT */

		last_semicolon = g_strrstr(url_wrk, ":");
		if (!last_semicolon || last_semicolon - url_wrk >= len)
			return 0;

		*(last_semicolon - 1) = '\0';
		*port = &(last_semicolon[1]);
		*host = &(url_wrk[1]);
		return 1;
	}

	last_semicolon = g_strrstr(url_wrk, ":");
	if (!last_semicolon || last_semicolon - url_wrk >= len)
		return 0;

	*last_semicolon = '\0';
	*port = &(last_semicolon[1]);
	*host = &(url_wrk[0]);
	return 1;
}

int
__open_unix_client(const char *path)
{
	int sock;
	struct sockaddr_un local;

	memset(&local, 0x00, sizeof(local));
	if (!path || strlen(path) >= sizeof(local.sun_path)) {
		errno = EINVAL;
		return -1;
	}

	/* Create ressources to monitor */
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

#if 0
	/* Got to non-blocking mode */
	if (-1 == fcntl(sock, F_SETFL, O_NONBLOCK))
		goto label_error;
#endif

	/* Bind to file */
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, path, sizeof(local.sun_path)-1);

	if (-1 == connect(sock, (struct sockaddr *)&local, sizeof(local)))
		goto label_error;

	errno = 0;
	return sock;

label_error:
	if (sock >= 0) {
		typeof(errno) errsav;
		errsav = errno;
		close(sock);
		errno = errsav;
	}
	return -1;
}

int
__open_unix_server(const char *path)
{
	int sock;
	struct sockaddr_un local;

	memset(&local, 0x00, sizeof(local));
	if (!path || strlen(path) >= sizeof(local.sun_path)) {
		errno = EINVAL;
		return -1;
	}

	/* Create ressources to monitor */
#ifdef SOCK_CLOEXEC
# define SOCK_FLAGS SOCK_CLOEXEC
#else
# define SOCK_FLAGS 0
#endif

	sock = socket(PF_UNIX, SOCK_STREAM | SOCK_FLAGS, 0);
	if (sock < 0)
		return -1;

#ifndef SOCK_CLOEXEC
# ifdef FD_CLOEXEC
	(void) fcntl(sock, F_SETFD, fcntl(sock, F_GETFD)|FD_CLOEXEC);
# endif
#endif

	/* Bind to file */
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, path, sizeof(local.sun_path)-1);

	if (-1 == bind(sock, (struct sockaddr *)&local, sizeof(local)))
		goto label_error;

	/* Listen on that socket */
	if (-1 == listen(sock, backlog_unix))
		goto label_error;

	errno = 0;
	return sock;

label_error:
	if (sock >= 0) {
		typeof(errno) errsav;
		errsav = errno;
		close(sock);
		errno = errsav;
	}
	return -1;
}

int
__open_inet_server(const char *url)
{
	gchar url_wrk[512];
	
	int sock = -1;
	int i_opt = 1;
	struct sockaddr_in sin;
	gchar *host=NULL, *port=NULL;

	memset(url_wrk, 0x00, sizeof(url_wrk));
	g_strlcpy(url_wrk, url, sizeof(url_wrk)-1);

	if (!__addr_split(url_wrk, &host, &port)) {
		errno = EINVAL;
		return -1;
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		/* transmit the errno as is */
		return -1;
	}

	/* SO_REUSEADDR */
	i_opt = 1;
	if (0 != setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, (void*) &i_opt, sizeof(i_opt)))
		WARN("Cannot set SO_REUSEADDR flag on socket %d (%s)", sock, strerror(errno));

	/* bind on the given URL then wait for incoming connections */
	memset(&sin, 0x00, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(port));
	if (!inet_aton(host, &(sin.sin_addr)))
		goto label_error;

	if (-1 == bind(sock, (struct sockaddr *)&sin, sizeof(sin)))
		goto label_error;

	if (-1 == listen(sock, backlog_tcp))
		goto label_error;

	errno = 0;
	return sock;

label_error:
	if (sock >= 0) {
		typeof(errno) errsav;
		errsav = errno;
		close(sock);
		errno = errsav;
	}
	return -1;
}


