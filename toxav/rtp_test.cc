#include "rtp.h"

#include <gtest/gtest.h>

#include "../toxcore/crypto_core.h"

namespace {

RTPHeader random_header(const Random *rng)
{
    return {
        random_u16(rng),
        random_u16(rng),
        random_u16(rng),
        random_u16(rng),
        random_u16(rng),
        random_u16(rng),
        random_u16(rng),
        random_u32(rng),
        random_u32(rng),
        random_u64(rng),
        random_u32(rng),
        random_u32(rng),
        random_u32(rng),
        random_u16(rng),
        random_u16(rng),
    };
}

TEST(Rtp, Deserialisation)
{
    const Random *rng = os_random();
    ASSERT_NE(rng, nullptr);
    RTPHeader const header = random_header(rng);

    uint8_t rdata[RTP_HEADER_SIZE];
    EXPECT_EQ(rtp_header_pack(rdata, &header), RTP_HEADER_SIZE);

    RTPHeader unpacked = {0};
    EXPECT_EQ(rtp_header_unpack(rdata, &unpacked), RTP_HEADER_SIZE);

    EXPECT_EQ(header.ve, unpacked.ve);
    EXPECT_EQ(header.pe, unpacked.pe);
    EXPECT_EQ(header.xe, unpacked.xe);
    EXPECT_EQ(header.cc, unpacked.cc);
    EXPECT_EQ(header.ma, unpacked.ma);
    EXPECT_EQ(header.pt, unpacked.pt);
    EXPECT_EQ(header.sequnum, unpacked.sequnum);
    EXPECT_EQ(header.timestamp, unpacked.timestamp);
    EXPECT_EQ(header.ssrc, unpacked.ssrc);
    EXPECT_EQ(header.flags, unpacked.flags);
    EXPECT_EQ(header.offset_full, unpacked.offset_full);
    EXPECT_EQ(header.data_length_full, unpacked.data_length_full);
    EXPECT_EQ(header.received_length_full, unpacked.received_length_full);
    EXPECT_EQ(header.offset_lower, unpacked.offset_lower);
    EXPECT_EQ(header.data_length_lower, unpacked.data_length_lower);
}

TEST(Rtp, SerialisingAllOnes)
{
    RTPHeader header;
    memset(&header, 0xff, sizeof header);

    uint8_t rdata[RTP_HEADER_SIZE];
    rtp_header_pack(rdata, &header);

    EXPECT_EQ(std::string(reinterpret_cast<char const *>(rdata), sizeof rdata),
        std::string("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            RTP_HEADER_SIZE));
}

}  // namespace
