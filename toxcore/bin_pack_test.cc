#include "bin_pack.h"

#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <vector>

#include "bin_unpack.h"

namespace {

struct Bin_Pack_Deleter {
    void operator()(Bin_Pack *bp) const { bin_pack_free(bp); }
};

using Bin_Pack_Ptr = std::unique_ptr<Bin_Pack, Bin_Pack_Deleter>;

struct Bin_Unpack_Deleter {
    void operator()(Bin_Unpack *bu) const { bin_unpack_free(bu); }
};

using Bin_Unpack_Ptr = std::unique_ptr<Bin_Unpack, Bin_Unpack_Deleter>;

TEST(BinPack, TooSmallBufferIsNotExceeded)
{
    std::array<uint8_t, 7> buf;
    Bin_Pack_Ptr bp(bin_pack_new(buf.data(), buf.size()));
    ASSERT_NE(bp, nullptr);
    EXPECT_FALSE(bin_pack_u64_b(bp.get(), 1234567812345678LL));
}

TEST(BinPack, PackedUint64CanBeUnpacked)
{
    std::array<uint8_t, 8> buf;
    Bin_Pack_Ptr bp(bin_pack_new(buf.data(), buf.size()));
    ASSERT_NE(bp, nullptr);
    ASSERT_TRUE(bin_pack_u64_b(bp.get(), 1234567812345678LL));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint64_t val;
    ASSERT_TRUE(bin_unpack_u64_b(bu.get(), &val));
    EXPECT_EQ(val, 1234567812345678LL);
}

TEST(BinPack, MsgPackedUint8CanBeUnpackedAsUint32)
{
    std::array<uint8_t, 2> buf;
    Bin_Pack_Ptr bp(bin_pack_new(buf.data(), buf.size()));
    ASSERT_NE(bp, nullptr);
    ASSERT_TRUE(bin_pack_u08(bp.get(), 123));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint32_t val;
    ASSERT_TRUE(bin_unpack_u32(bu.get(), &val));
    EXPECT_EQ(val, 123);
}

TEST(BinPack, MsgPackedUint32CanBeUnpackedAsUint8IfSmallEnough)
{
    std::array<uint8_t, 2> buf;
    Bin_Pack_Ptr bp(bin_pack_new(buf.data(), buf.size()));
    ASSERT_NE(bp, nullptr);
    ASSERT_TRUE(bin_pack_u32(bp.get(), 123));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint8_t val;
    ASSERT_TRUE(bin_unpack_u08(bu.get(), &val));
    EXPECT_EQ(val, 123);
}

TEST(BinPack, LargeMsgPackedUint32CannotBeUnpackedAsUint8)
{
    std::array<uint8_t, 5> buf;
    Bin_Pack_Ptr bp(bin_pack_new(buf.data(), buf.size()));
    ASSERT_NE(bp, nullptr);
    ASSERT_TRUE(bin_pack_u32(bp.get(), 1234567));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint8_t val;
    EXPECT_FALSE(bin_unpack_u08(bu.get(), &val));
}

}  // namespace
