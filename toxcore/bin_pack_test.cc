#include "bin_pack.h"

#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <vector>

#include "bin_unpack.h"
#include "logger.h"

namespace {

TEST(BinPack, TooSmallBufferIsNotExceeded)
{
    const uint64_t orig = 1234567812345678LL;
    std::array<uint8_t, sizeof(orig) - 1> buf;
    EXPECT_FALSE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_u64_b(bp, *static_cast<const uint64_t *>(obj));
        },
        &orig, nullptr, buf.data(), buf.size()));
}

TEST(BinPack, PackedUint64CanBeUnpacked)
{
    const uint64_t orig = 1234567812345678LL;
    std::array<uint8_t, 8> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_u64_b(bp, *static_cast<const uint64_t *>(obj));
        },
        &orig, nullptr, buf.data(), buf.size()));

    uint64_t unpacked;
    EXPECT_TRUE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) {
            return bin_unpack_u64_b(bu, static_cast<uint64_t *>(obj));
        },
        &unpacked, buf.data(), buf.size()));
    EXPECT_EQ(unpacked, 1234567812345678LL);
}

TEST(BinPack, MsgPackedUint8CanBeUnpackedAsUint32)
{
    const uint8_t orig = 123;
    std::array<uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_u08(bp, *static_cast<const uint8_t *>(obj));
        },
        &orig, nullptr, buf.data(), buf.size()));

    uint32_t unpacked;
    EXPECT_TRUE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) { return bin_unpack_u32(bu, static_cast<uint32_t *>(obj)); },
        &unpacked, buf.data(), buf.size()));
    EXPECT_EQ(unpacked, 123);
}

TEST(BinPack, MsgPackedUint32CanBeUnpackedAsUint8IfSmallEnough)
{
    const uint32_t orig = 123;
    std::array<uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_u32(bp, *static_cast<const uint32_t *>(obj));
        },
        &orig, nullptr, buf.data(), buf.size()));

    uint8_t unpacked;
    EXPECT_TRUE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) { return bin_unpack_u08(bu, static_cast<uint8_t *>(obj)); },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked, 123);
}

TEST(BinPack, LargeMsgPackedUint32CannotBeUnpackedAsUint8)
{
    const uint32_t orig = 1234567;
    std::array<uint8_t, 5> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_u32(bp, *static_cast<const uint32_t *>(obj));
        },
        &orig, nullptr, buf.data(), buf.size()));

    uint8_t unpacked;
    EXPECT_FALSE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) { return bin_unpack_u08(bu, static_cast<uint8_t *>(obj)); },
        &unpacked, buf.data(), buf.size()));
}

TEST(BinPack, BinCanHoldPackedInts)
{
    struct Stuff {
        uint64_t u64;
        uint16_t u16;
    };
    const Stuff orig = {1234567812345678LL, 54321};
    static const uint32_t packed_size = sizeof(uint64_t) + sizeof(uint16_t);

    std::array<uint8_t, 12> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            const Stuff *self = static_cast<const Stuff *>(obj);
            return bin_pack_bin_marker(bp, packed_size)  //
                && bin_pack_u64_b(bp, self->u64)  //
                && bin_pack_u16_b(bp, self->u16);
        },
        &orig, nullptr, buf.data(), buf.size()));

    Stuff unpacked;
    EXPECT_TRUE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) {
            Stuff *stuff = static_cast<Stuff *>(obj);
            uint32_t size;
            return bin_unpack_bin_size(bu, &size)  //
                && size == 10  //
                && bin_unpack_u64_b(bu, &stuff->u64)  //
                && bin_unpack_u16_b(bu, &stuff->u16);
        },
        &unpacked, buf.data(), buf.size()));
    EXPECT_EQ(unpacked.u64, 1234567812345678LL);
    EXPECT_EQ(unpacked.u16, 54321);
}

TEST(BinPack, BinCanHoldArbitraryData)
{
    std::array<uint8_t, 7> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_bin_marker(bp, 5)  //
                && bin_pack_bin_b(bp, reinterpret_cast<const uint8_t *>("hello"), 5);
        },
        nullptr, nullptr, buf.data(), buf.size()));

    std::array<uint8_t, 5> str;
    EXPECT_TRUE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) {
            uint8_t *data = static_cast<uint8_t *>(obj);
            return bin_unpack_bin_fixed(bu, data, 5);
        },
        str.data(), buf.data(), buf.size()));
    EXPECT_EQ(str, (std::array<uint8_t, 5>{'h', 'e', 'l', 'l', 'o'}));
}

TEST(BinPack, OversizedArrayFailsUnpack)
{
    std::array<uint8_t, 1> buf = {0x91};

    uint32_t size;
    EXPECT_FALSE(bin_unpack_obj(
        [](void *obj, Bin_Unpack *bu) {
            uint32_t *size_ptr = static_cast<uint32_t *>(obj);
            return bin_unpack_array(bu, size_ptr);
        },
        &size, buf.data(), buf.size()));
}

}  // namespace
