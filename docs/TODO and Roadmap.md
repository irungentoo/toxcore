ALPHA:

    DHT
        [IN PROGRESS] Metadata collection prevention. (docs/Prevent_Tracking.txt)
        [IN PROGRESS] Hardening against attacks.
        [IN PROGRESS] Optimizing the code.

    [NEEDS TESTING] Make the save made with tox_save_encrypted(...) harder to brute force.
                    See: (https://github.com/jencka/ProjectTox-libtoxdata)

    [IN PROGRESS] GUI (no official GUI chosen yet, will most likely be: 
                  https://github.com/nurupo/ProjectTox-Qt-GUI or https://github.com/naxuroqa/Venom)

BETA:

    Massive IRC like group chats (text only)
        [DONE] Networking base.
        [NOT STARTED] Syncing chat state between clients (nicknames, list of who is in chat, etc...)
        [NOT STARTED] Make clients sign their messages so that peers can't modify them.

    Audio/Video
        [DONE] Capture/encoding/streaming/decoding/displaying
        [IN PROGRESS] Call initiation
        [NOT STARTED] Encryption
        [NOT STARTED] Small group chats
        [NOT STARTED] Push to talk for audio

    [NOT STARTED] Offline messaging

    IPV6 support:
        [DONE] Networking
        [DONE] DHT + Messenger
        [NOT STARTED] Group chats (They work with IPv6 but some things need to be tested.)

GAMMA:

    Networking:
        [NOT STARTED] UPnP port forwarding.
        [NOT STARTED] NAT-PMP port forwarding.

    Friend_requests.c:
        [NOT STARTED] What happens when a friend request is recieved needs to be changed.

STABLE:

    [NOT STARTED] Security audit from independent professionals
    [NOT STARTED] Bug fixes after a complete testing in the gamma phase
