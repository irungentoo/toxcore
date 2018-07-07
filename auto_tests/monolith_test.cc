/* Nop-test, just to make sure our code compiles as C++.
 */

#ifdef __FreeBSD__
// Include this here, because _XOPEN_SOURCE hides symbols we need.
//
// https://lists.freebsd.org/pipermail/freebsd-standards/2004-March/000474.html.
#include <net/if.h>
#endif

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../other/monolith.h"
#define DHT_C_INCLUDED

#include "../testing/misc_tools.c"
#include "check_compat.h"
#include "helpers.h"

#include <ctype.h>

namespace TCP_test {
int main(void);
#include "TCP_test.c"
}  // namespace TCP_test
namespace bootstrap_test {
int main(void);
#include "bootstrap_test.c"
}  // namespace bootstrap_test
namespace conference_simple_test {
int main(void);
#include "conference_simple_test.c"
}  // namespace conference_simple_test
namespace conference_test {
int main(void);
#include "conference_test.c"
}  // namespace conference_test
namespace crypto_test {
int main(void);
#include "crypto_test.c"
}  // namespace crypto_test
namespace dht_test {
int main(void);
#include "dht_test.c"
}  // namespace dht_test
namespace encryptsave_test {
int main(void);
#include "encryptsave_test.c"
}  // namespace encryptsave_test
namespace file_saving_test {
int main(void);
#include "file_saving_test.c"
}  // namespace file_saving_test
namespace friend_request_test {
int main(void);
#include "friend_request_test.c"
}  // namespace friend_request_test
namespace lan_discovery_test {
int main(void);
#include "lan_discovery_test.c"
}  // namespace lan_discovery_test
namespace lossless_packet_test {
int main(void);
#include "lossless_packet_test.c"
}  // namespace lossless_packet_test
namespace lossy_packet_test {
int main(void);
#include "lossy_packet_test.c"
}  // namespace lossy_packet_test
namespace messenger_test {
int main(void);
#include "messenger_test.c"
}  // namespace messenger_test
namespace network_test {
int main(void);
#include "network_test.c"
}  // namespace network_test
namespace onion_test {
int main(void);
#include "onion_test.c"
}  // namespace onion_test
namespace save_friend_test {
int main(void);
#include "save_friend_test.c"
}  // namespace save_friend_test
namespace save_load_test {
int main(void);
#include "save_load_test.c"
}  // namespace save_load_test
namespace send_message_test {
int main(void);
#include "send_message_test.c"
}  // namespace send_message_test
namespace set_name_test {
int main(void);
#include "set_name_test.c"
}  // namespace set_name_test
namespace set_status_message_test {
int main(void);
#include "set_status_message_test.c"
}  // namespace set_status_message_test
namespace skeleton_test {
int main(void);
#include "skeleton_test.c"
}  // namespace skeleton_test
namespace toxav_basic_test {
int main(void);
#include "toxav_basic_test.c"
}  // namespace toxav_basic_test
namespace toxav_many_test {
int main(void);
#include "toxav_many_test.c"
}  // namespace toxav_many_test
namespace tox_many_tcp_test {
int main(void);
#include "tox_many_tcp_test.c"
}  // namespace tox_many_tcp_test
namespace tox_many_test {
int main(void);
#include "tox_many_test.c"
}  // namespace tox_many_test
namespace tox_one_test {
int main(void);
#include "tox_one_test.c"
}  // namespace tox_one_test
namespace tox_strncasecmp_test {
int main(void);
#include "tox_strncasecmp_test.c"
}  // namespace tox_strncasecmp_test
namespace typing_test {
int main(void);
#include "typing_test.c"
}  // namespace typing_test
namespace version_test {
int main(void);
#include "version_test.c"
}  // namespace version_test

#define PRINT_SIZE 0

template <typename T, size_t Expected, size_t Actual = sizeof(T)>
void check_size(char const *type) {
#if PRINT_SIZE
  printf("CHECK_SIZE(%s, %zu);\n", type, Actual);
#else
  static_assert(Actual == Expected, "Bad sizeof - see template expansion errors for details");
#endif
}

#define CHECK_SIZE(TYPE, SIZE) check_size<TYPE, SIZE>(#TYPE)

/**
 * The main function static-asserts that we are aware of all the sizes of all
 * the structs it toxcore. If you find this failing after you make a change,
 * switch on the PRINT_SIZE above and copy the number into this function.
 */
int main(int argc, char *argv[]) {
#if defined(__x86_64__) && defined(__LP64__)
  // toxcore/DHT
  CHECK_SIZE(Client_data, 496);
  CHECK_SIZE(Cryptopacket_Handles, 16);
  CHECK_SIZE(DHT, 676528);
  CHECK_SIZE(DHT_Friend, 5104);
  CHECK_SIZE(Hardening, 144);
  CHECK_SIZE(IPPTs, 40);
  CHECK_SIZE(IPPTsPng, 232);
  CHECK_SIZE(NAT, 48);
  CHECK_SIZE(Node_format, 64);
  CHECK_SIZE(Shared_Key, 80);
  CHECK_SIZE(Shared_Keys, 81920);
  // toxcore/friend_connection
  CHECK_SIZE(Friend_Conn, 1784);
  CHECK_SIZE(Friend_Connections, 72);
  // toxcore/friend_requests
  CHECK_SIZE(Friend_Requests, 1080);
  // toxcore/group
  CHECK_SIZE(Group_c, 728);
  CHECK_SIZE(Group_Chats, 2120);
  CHECK_SIZE(Group_Peer, 480);
  // toxcore/list
  CHECK_SIZE(BS_LIST, 32);
  // toxcore/logger
  CHECK_SIZE(Logger, 24);
  // toxcore/Messenger
  CHECK_SIZE(File_Transfers, 72);
  CHECK_SIZE(Friend, 39264);
  CHECK_SIZE(Messenger, 2008);
  CHECK_SIZE(Messenger_Options, 72);
  CHECK_SIZE(Receipts, 16);
  // toxcore/net_crypto
#ifdef __linux__
  CHECK_SIZE(Crypto_Connection, 525392);
  CHECK_SIZE(Net_Crypto, 272);
#endif
  CHECK_SIZE(New_Connection, 168);
  CHECK_SIZE(Packet_Data, 1384);
  CHECK_SIZE(Packets_Array, 262152);
  // toxcore/network
  CHECK_SIZE(IP, 24);
  CHECK_SIZE(IP4, 4);
#if USE_IPV6
  CHECK_SIZE(IP6, 16);
#endif
  CHECK_SIZE(IP_Port, 32);
  CHECK_SIZE(Networking_Core, 4112);
  CHECK_SIZE(Packet_Handler, 16);
  // toxcore/onion_announce
  CHECK_SIZE(Cmp_data, 296);
  CHECK_SIZE(Onion_Announce, 128048);
  CHECK_SIZE(Onion_Announce_Entry, 288);
  // toxcore/onion_client
  CHECK_SIZE(Last_Pinged, 40);
  CHECK_SIZE(Onion_Client, 15816);
  CHECK_SIZE(Onion_Client_Cmp_data, 176);
  CHECK_SIZE(Onion_Client_Paths, 2520);
  CHECK_SIZE(Onion_Friend, 1936);
  CHECK_SIZE(Onion_Friend, 1936);
  CHECK_SIZE(Onion_Node, 168);
  // toxcore/onion
  CHECK_SIZE(Onion, 245832);
  CHECK_SIZE(Onion_Path, 392);
  // toxcore/ping_array
  CHECK_SIZE(Ping_Array, 24);
  CHECK_SIZE(Ping_Array_Entry, 32);
  // toxcore/ping
  CHECK_SIZE(Ping, 2072);
  // toxcore/TCP_client
  CHECK_SIZE(TCP_Client_Connection, 12064);
  CHECK_SIZE(TCP_Proxy_Info, 40);
  // toxcore/TCP_connection
  CHECK_SIZE(TCP_con, 112);
  CHECK_SIZE(TCP_Connections, 200);
  CHECK_SIZE(TCP_Connection_to, 112);
  // toxcore/TCP_server
  CHECK_SIZE(TCP_Priority_List, 16);
  CHECK_SIZE(TCP_Secure_Connection, 11816);
#ifdef TCP_SERVER_USE_EPOLL
  CHECK_SIZE(TCP_Server, 6049968);  // 6MB!
#else
  CHECK_SIZE(TCP_Server, 6049952);  // 6MB!
#endif
  // toxcore/tox
  CHECK_SIZE(Tox_Options, 64);
#endif
  return 0;
}
