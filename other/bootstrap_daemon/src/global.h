/*
 * Tox DHT bootstrap daemon.
 * Globally used defines.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014-2016 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_GLOBAL_H
#define C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_GLOBAL_H

#include "../../../toxcore/tox.h"

#define DAEMON_NAME "tox-bootstrapd"

#define DAEMON_VERSION_MAJOR TOX_VERSION_MAJOR
#define DAEMON_VERSION_MINOR TOX_VERSION_MINOR
#define DAEMON_VERSION_PATCH TOX_VERSION_PATCH

// Make sure versions are within the limit
#define VERSION_IS_OK(NUM) ( NUM >= 0 && NUM <= 999 )
#if !VERSION_IS_OK(DAEMON_VERSION_MAJOR) || !VERSION_IS_OK(DAEMON_VERSION_MINOR) || !VERSION_IS_OK(DAEMON_VERSION_PATCH)
#error "At least one of major, minor or patch parts of the version is out of bounds of [0, 999]. Current version: " DAEMON_VERSION_MAJOR "." DAEMON_VERSION_MINOR "." DAEMON_VERSION_PATCH
#endif
#undef VERSION_IS_OK

// New version scheme of 1AAABBBCCC, where A B and C are major, minor and patch
// versions of toxcore. The leading 1 is there just to keep the leading zeros,
// so that it would be easier to read the version when printed as a number.
// The version is in a visual decimal format rather than in any other format,
// because the original version was using a similar format, it was using
// YYYYMMDDVV date-based format for the version, with VV being an incremental
// counter in case more than one version was released at that day. Due to this
// some tools started showing the version to users as a plain number, rather
// than some binary format that needs to be parsed before being shown to users
// so we decided to keep this display format compatibility and adopted this
// weird scheme with a leading 1.
#define DAEMON_VERSION_NUMBER 1000000000UL + DAEMON_VERSION_MAJOR*1000000UL + DAEMON_VERSION_MINOR*1000UL + DAEMON_VERSION_PATCH*1UL

#define MIN_ALLOWED_PORT 1
#define MAX_ALLOWED_PORT 65535

#endif // C_TOXCORE_OTHER_BOOTSTRAP_DAEMON_SRC_GLOBAL_H
