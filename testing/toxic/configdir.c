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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef WIN32
#include <shlobj.h>
#include <direct.h>
#else /* WIN32 */
#include <unistd.h>
#include <pwd.h>
#endif /* WIN32 */

#include "configdir.h"

/**
 * @brief Get the users config directory.
 *
 * This is without a trailing slash.
 *
 * @return The users config dir or NULL on error.
 */
char *get_user_config_dir(void)
{
    char *user_config_dir;
#ifdef WIN32
    char appdata[MAX_PATH];
    BOOL ok;

    ok = SHGetSpecialFolderPathA(NULL, appdata, CSIDL_PROFILE, TRUE);

    if (!ok) {
        return NULL;
    }

    user_config_dir = strdup(appdata);

    return user_config_dir;

#else /* WIN32 */

#ifndef NSS_BUFLEN_PASSWD
#define NSS_BUFLEN_PASSWD 4096
#endif /* NSS_BUFLEN_PASSWD */

    struct passwd pwd;
    struct passwd *pwdbuf;
    const char *home;
    char buf[NSS_BUFLEN_PASSWD];
    size_t len;
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);

    if (rc == 0) {
        home = pwd.pw_dir;
    } else {
        home = getenv("HOME");

        if (home == NULL) {
            return NULL;
        }

        /* env variables can be tainted */
        snprintf(buf, sizeof(buf), "%s", home);
        home = buf;
    }

# if defined(__APPLE__)
    len = strlen(home) + strlen("/Library/Application Support") + 1;
    user_config_dir = malloc(len);

    if (user_config_dir == NULL) {
        return NULL;
    }

    snprintf(user_config_dir, len, "%s/Library/Application Support", home);
# else /* __APPLE__ */
    len = strlen(home) + strlen("/.config") + 1;
    user_config_dir = malloc(len);

    if (user_config_dir == NULL) {
        return NULL;
    }

    snprintf(user_config_dir, len, "%s/.config", home);
# endif /* __APPLE__ */

    return user_config_dir;
#undef NSS_BUFLEN_PASSWD
#endif /* WIN32 */
}

/*
 * Creates the config directory.
 */
int create_user_config_dir(char *path)
{

    int mkdir_err;

#ifdef WIN32

    char *fullpath = malloc(strlen(path) + strlen(CONFIGDIR) + 1);
    strcpy(fullpath, path);
    strcat(fullpath, CONFIGDIR);

    mkdir_err = _mkdir(fullpath);
    struct __stat64 buf;

    if (mkdir_err && (errno != EEXIST || _wstat64(fullpath, &buf) || !S_ISDIR(buf.st_mode))) {
        free(fullpath);
        return -1;
    }

#else

    mkdir_err = mkdir(path, 0700);
    struct stat buf;

    if (mkdir_err && (errno != EEXIST || stat(path, &buf) || !S_ISDIR(buf.st_mode))) {
        return -1;
    }

    char *fullpath = malloc(strlen(path) + strlen(CONFIGDIR) + 1);
    strcpy(fullpath, path);
    strcat(fullpath, CONFIGDIR);

    mkdir_err = mkdir(fullpath, 0700);

    if (mkdir_err && (errno != EEXIST || stat(fullpath, &buf) || !S_ISDIR(buf.st_mode))) {
        free(fullpath);
        return -1;
    }

#endif
    free(fullpath);
    return 0;
}
