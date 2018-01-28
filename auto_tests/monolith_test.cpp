/* Auto Tests: One instance.
 */

#define _DARWIN_C_SOURCE
#define _XOPEN_SOURCE 600

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../other/monolith.h"
#define DHT_C_INCLUDED

#include "check_compat.h"
#include "helpers.h"
#include "../testing/misc_tools.c"

#include <ctype.h>

namespace TCP_test {
#include "TCP_test.c"
}
namespace conference_test {
#include "conference_test.c"
}
namespace crypto_test {
#include "crypto_test.c"
}
namespace dht_test {
#include "dht_test.c"
}
namespace encryptsave_test {
#include "encryptsave_test.c"
}
namespace file_saving_test {
#include "file_saving_test.c"
}
namespace messenger_test {
#include "messenger_test.c"
}
namespace network_test {
#include "network_test.c"
}
namespace onion_test {
#include "onion_test.c"
}
namespace resource_leak_test {
#include "resource_leak_test.c"
}
namespace save_friend_test {
#include "save_friend_test.c"
}
namespace selfname_change_conference_test {
#include "selfname_change_conference_test.c"
}
namespace self_conference_title_change_test {
#include "self_conference_title_change_test.c"
}
namespace simple_conference_test {
#include "simple_conference_test.c"
}
namespace skeleton_test {
#include "skeleton_test.c"
}
namespace toxav_basic_test {
#include "toxav_basic_test.c"
}
namespace toxav_many_test {
#include "toxav_many_test.c"
}
namespace tox_many_tcp_test {
#include "tox_many_tcp_test.c"
}
namespace tox_many_test {
#include "tox_many_test.c"
}
namespace tox_one_test {
#include "tox_one_test.c"
}
namespace tox_strncasecmp_test {
#include "tox_strncasecmp_test.c"
}
namespace tox_test {
#include "tox_test.c"
}
namespace version_test {
#include "version_test.c"
}

int main(int argc, char *argv[])
{
    return 0;
}
