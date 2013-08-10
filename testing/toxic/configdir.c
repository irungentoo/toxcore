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
#endif

#ifdef __APPLE__
#include <unistd.h>
#include <pwd.h>
#endif

#include "configdir.h"

/*
 * Retrieves a correct configuration directory, depending on the OS used, with a trailing slash
 */
char *get_user_config_dir(void)
{
  char *user_config_dir;

  #ifdef WIN32

  char appdata[MAX_PATH];
  HRESULT result = SHGetFolderPath(
    NULL,
    CSIDL_APPDATA,
    NULL,
    SHGFP_TYPE_CURRENT,
    appdata
  )
  if (!result) return NULL;

  user_config_dir = strdup(appdata);

  return user_config_dir;

  #elif defined __APPLE__

  struct passwd *pass = getpwuid(getuid());
  if (!pass) return NULL;
  char *home = pass->pw_dir;
  user_config_dir = malloc(strlen(home) + strlen("/Library/Application Support") + 1);
  
  if(user_config_dir) {
    strcpy(user_config_dir, home);
    strcat(user_config_dir, "/Library/Application Support");
  }
  return user_config_dir;

  #else

  if (getenv("XDG_CONFIG_HOME")) {
    user_config_dir = strdup(getenv("XDG_CONFIG_HOME"));
  } else {
    user_config_dir = malloc(strlen(getenv("HOME")) + strlen("/.config") + 1);
    if (user_config_dir) {
      strcpy(user_config_dir, getenv("HOME"));
      strcat(user_config_dir, "/.config");
    }
  }
  return user_config_dir;

  #endif
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

  if(mkdir_err && (errno != EEXIST || stat(path, &buf) || !S_ISDIR(buf.st_mode))) {
    return -1;
  }

  char *fullpath = malloc(strlen(path) + strlen(CONFIGDIR) + 1);
  strcpy(fullpath, path);
  strcat(fullpath, CONFIGDIR);

  mkdir_err = mkdir(fullpath, 0700);

  if(mkdir_err && (errno != EEXIST || stat(fullpath, &buf) || !S_ISDIR(buf.st_mode))) {
    free(fullpath);
    return -1;
  }
    
  #endif
  free(fullpath);
  return 0;
}
