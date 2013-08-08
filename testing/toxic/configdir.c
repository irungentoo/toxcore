/*
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _win32
#include <shlobj.h>
#endif

#ifdef __APPLE__
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#endif

char *get_user_config_dir(void)
{
	char *user_config_dir;

	#ifdef _win32

	char appdata[MAX_PATH];
	HRESULT result = SHGetFolderPath(
		NULL,
		CSIDL_APPDATA, // TODO: Maybe use CSIDL_LOCAL_APPDATA instead? Not sure.
		NULL,
		SHGFP_TYPE_CURRENT,
		appdata
	)
	if (!result) return NULL;

	user_config_dir = malloc(strlen(appdata) + strlen(CONFIGDIR) + 1);
	if (user_config_dir) {
		strcpy(user_config_dir, appdata);
		strcat(user_config_dir, CONFIGDIR);
	}
	return user_config_dir;

	#elif defined __APPLE__

	struct passwd *pass = getpwuid(getuid());
	if (!pass) return NULL;
	char *home = pass->pw_dir;
	user_config_dir = malloc(strlen(home) + strlen("/Library/Application Support") + strlen(CONFIGDIR) + 1);
	
	if(user_config_dir) {
		strcpy(user_config_dir, home);
		strcat(user_config_dir, "/Library/Application Support");
		strcat(user_config_dir, CONFIGDIR);
	}
	return user_config_dir;

	#else

	if (getenv("XDG_CONFIG_HOME")) {
		user_config_dir = malloc(strlen(getenv("XDG_CONFIG_HOME")) + strlen(CONFIGDIR) + 1);
		if (user_config_dir) {
			strcpy(user_config_dir, getenv("XDG_CONFIG_HOME"));
			strcat(user_config_dir, CONFIGDIR);
		}
	} else {
		user_config_dir = malloc(strlen(getenv("HOME")) + strlen("/.config") + strlen(CONFIGDIR) + 1);
		if (user_config_dir) {
			strcpy(user_config_dir, getenv("HOME"));
			strcat(user_config_dir, "/.config");
			strcat(user_config_dir, CONFIGDIR);
		}
	}
	return user_config_dir;

	#endif
}