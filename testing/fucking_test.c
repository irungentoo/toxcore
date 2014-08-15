#include "../toxcore/tox.h"
#include "../toxcore/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/ping.h"
#include "../toxcore/util.h"
#include "../toxcore/group_chats_new.h"

#include <stdio.h>
#include <stdlib.h>

int main()
{
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

	crypto_box_keypair(pk, sk);

    uint8_t  lpk1[EXT_PUBLIC_KEY];
    uint8_t  lpk2[EXT_PUBLIC_KEY];
    uint8_t  lsk1[EXT_SECRET_KEY];
    uint8_t  lsk2[EXT_SECRET_KEY];

	create_long_keypair(lpk1, lsk1);
	create_long_keypair(lpk2, lsk2);

    printf("ID1: %s\n", id_toa(lpk1));
    printf("ID2: %s\n", id_toa(lpk2));

	if (id_equal(pk, sk))
        printf("FUCK!\n");
    else
        printf("Hurray!\n");

	if (id_long_equal(lpk1, lpk2))
        printf("FUCK!\n");
    else
        printf("Hurray!\n");
}