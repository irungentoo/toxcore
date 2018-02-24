CPPFLAGS="-DMIN_LOGGER_LEVEL=LOG_TRACE -Iauto_tests -Itoxcore -Itoxav -Itoxencryptsave `pkg-config --cflags libsodium opus vpx`"

put() {
  if [ "$SKIP_LINES" = "" ]; then
    echo "#line 1 \"$1\"" >> test.c
  fi
  cat $1 >> test.c
}

:> test.c

put toxcore/tox.c

put toxcore/DHT.c
put toxcore/LAN_discovery.c
put toxcore/Messenger.c
put toxcore/TCP_client.c
put toxcore/TCP_connection.c
put toxcore/TCP_server.c
put toxcore/crypto_core.c
put toxcore/crypto_core_mem.c
put toxcore/friend_connection.c
put toxcore/friend_requests.c
put toxcore/group.c
put toxcore/list.c
put toxcore/logger.c
put toxcore/network.c
put toxcore/net_crypto.c
put toxcore/onion.c
put toxcore/onion_announce.c
put toxcore/onion_client.c
put toxcore/ping.c
put toxcore/ping_array.c
put toxcore/tox_api.c
put toxcore/util.c

# Not included yet, since there are too many issues with this code.
#put toxav/audio.c
#put toxav/bwcontroller.c
#put toxav/groupav.c
#put toxav/msi.c
#put toxav/ring_buffer.c
#put toxav/rtp.c
#put toxav/toxav.c
#put toxav/toxav_old.c
#put toxav/video.c

put toxencryptsave/toxencryptsave.c
