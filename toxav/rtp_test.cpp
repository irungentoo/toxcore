#include "rtp.h"

#include "../toxcore/crypto_core.h"

#include <gtest/gtest.h>

TEST(Rtp, Deserialisation) {
    RTPHeader header;
    random_bytes((uint8_t *)&header, sizeof header);

    uint8_t rdata[sizeof(RTPHeader)];
    EXPECT_EQ(rtp_header_pack(rdata, &header), RTP_HEADER_SIZE);

    RTPHeader unpacked;
    EXPECT_EQ(rtp_header_unpack(rdata, &unpacked), RTP_HEADER_SIZE);

    EXPECT_EQ(std::string((char const *)&header, sizeof header),
              std::string((char const *)&unpacked, sizeof unpacked));
}
