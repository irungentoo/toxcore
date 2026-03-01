#include "bin_pack.h"

#include <gtest/gtest.h>

#include <array>

#include "attributes.h"
#include "bin_unpack.h"
#include "logger.h"
#include "mem.h"
#include "os_memory.h"
#include "test_util.hh"

namespace {

TEST(BinPack, TooSmallBufferIsNotExceeded)
{
    const std::uint64_t orig = 1234567812345678LL;
    std::array<std::uint8_t, sizeof(orig) - 1> buf;
    EXPECT_FALSE(bin_pack_obj(
        [](const void *_Nullable obj, const Logger *_Nullable logger, Bin_Pack *_Nonnull bp) {
            return bin_pack_u64_b(bp, *static_cast<const std::uint64_t *>(REQUIRE_NOT_NULL(obj)));
        },
        &orig, nullptr, buf.data(), buf.size()));
}

TEST(BinPack, PackedUint64CanBeUnpacked)
{
    const Memory *_Nonnull mem = os_memory();
    const std::uint64_t orig = 1234567812345678LL;
    std::array<std::uint8_t, 8> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *_Nullable obj, const Logger *_Nullable logger, Bin_Pack *_Nonnull bp) {
            return bin_pack_u64_b(bp, *static_cast<const std::uint64_t *>(REQUIRE_NOT_NULL(obj)));
        },
        &orig, nullptr, buf.data(), buf.size()));

    std::uint64_t unpacked = 0;
    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *_Nonnull obj, Bin_Unpack *_Nonnull bu) {
            return bin_unpack_u64_b(bu, static_cast<std::uint64_t *>(obj));
        },
        &unpacked, buf.data(), buf.size()));
    EXPECT_EQ(unpacked, 1234567812345678LL);
}

TEST(BinPack, MsgPackedUint8CanBeUnpackedAsUint32)
{
    const Memory *_Nonnull mem = os_memory();
    const std::uint8_t orig = 123;
    std::array<std::uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *_Nullable obj, const Logger *_Nullable logger, Bin_Pack *_Nonnull bp) {
            return bin_pack_u08(bp, *static_cast<const std::uint8_t *>(REQUIRE_NOT_NULL(obj)));
        },
        &orig, nullptr, buf.data(), buf.size()));

    std::uint32_t unpacked = 0;
    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *_Nonnull obj, Bin_Unpack *_Nonnull bu) {
            return bin_unpack_u32(bu, static_cast<std::uint32_t *>(obj));
        },
        &unpacked, buf.data(), buf.size()));
    EXPECT_EQ(unpacked, 123);
}

TEST(BinPack, MsgPackedUint32CanBeUnpackedAsUint8IfSmallEnough)
{
    const Memory *_Nonnull mem = os_memory();
    const std::uint32_t orig = 123;
    std::array<std::uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *_Nullable obj, const Logger *_Nullable logger, Bin_Pack *_Nonnull bp) {
            return bin_pack_u32(bp, *static_cast<const std::uint32_t *>(REQUIRE_NOT_NULL(obj)));
        },
        &orig, nullptr, buf.data(), buf.size()));

    std::uint8_t unpacked = 0;
    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *_Nonnull obj, Bin_Unpack *_Nonnull bu) {
            return bin_unpack_u08(bu, static_cast<std::uint8_t *>(obj));
        },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked, 123);
}

TEST(BinPack, LargeMsgPackedUint32CannotBeUnpackedAsUint8)
{
    const Memory *mem = os_memory();
    const std::uint32_t orig = 1234567;
    std::array<std::uint8_t, 5> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_u32(bp, *static_cast<const std::uint32_t *>(obj));
        },
        &orig, nullptr, buf.data(), buf.size()));

    std::uint8_t unpacked = 0;
    EXPECT_FALSE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            return bin_unpack_u08(bu, static_cast<std::uint8_t *>(obj));
        },
        &unpacked, buf.data(), buf.size()));
}

TEST(BinPack, BinCanHoldPackedInts)
{
    const Memory *mem = os_memory();
    struct Stuff {
        std::uint64_t u64;
        std::uint16_t u16;
    };
    const Stuff orig = {1234567812345678LL, 54321};
    static const std::uint32_t packed_size = sizeof(std::uint64_t) + sizeof(std::uint16_t);

    std::array<std::uint8_t, 12> buf;
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
        mem,
        [](void *obj, Bin_Unpack *bu) {
            Stuff *stuff = static_cast<Stuff *>(obj);
            std::uint32_t size;
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
    const Memory *mem = os_memory();
    std::array<std::uint8_t, 7> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            return bin_pack_bin_marker(bp, 5)  //
                && bin_pack_bin_b(bp, reinterpret_cast<const std::uint8_t *>("hello"), 5);
        },
        nullptr, nullptr, buf.data(), buf.size()));

    std::array<std::uint8_t, 5> str;
    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            std::uint8_t *data = static_cast<std::uint8_t *>(obj);
            return bin_unpack_bin_fixed(bu, data, 5);
        },
        str.data(), buf.data(), buf.size()));
    EXPECT_EQ(str, (std::array<std::uint8_t, 5>{'h', 'e', 'l', 'l', 'o'}));
}

TEST(BinPack, OversizedArrayFailsUnpack)
{
    const Memory *mem = os_memory();
    std::array<std::uint8_t, 1> buf = {0x91};

    std::uint32_t size;
    EXPECT_FALSE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            std::uint32_t *size_ptr = static_cast<std::uint32_t *>(obj);
            return bin_unpack_array(bu, size_ptr);
        },
        &size, buf.data(), buf.size()));
}

TEST(BinPack, StringCanBePackedAndUnpacked)
{
    const Memory *mem = os_memory();
    const char *orig = "hello world";
    const uint32_t orig_len = strlen(orig);

    std::array<std::uint8_t, 13> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            const char *str = static_cast<const char *>(obj);
            return bin_pack_str(bp, str, strlen(str));
        },
        orig, nullptr, buf.data(), buf.size()));

    struct {
        char *str;
        uint32_t len;
    } unpacked = {nullptr, 0};

    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<decltype(unpacked) *>(obj);
            return bin_unpack_str(bu, &res->str, &res->len);
        },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked.len, orig_len);
    EXPECT_STREQ(unpacked.str, orig);
    mem_delete(mem, unpacked.str);
}

TEST(BinPack, EmptyStringCanBePackedAndUnpacked)
{
    const Memory *mem = os_memory();
    const char *orig = "";
    const uint32_t orig_len = 0;

    std::array<std::uint8_t, 1> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            const char *str = static_cast<const char *>(obj);
            return bin_pack_str(bp, str, 0);
        },
        orig, nullptr, buf.data(), buf.size()));

    struct {
        char *str;
        uint32_t len;
    } unpacked = {nullptr, 0};

    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<decltype(unpacked) *>(obj);
            return bin_unpack_str(bu, &res->str, &res->len);
        },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked.len, orig_len);
    EXPECT_STREQ(unpacked.str, orig);
    mem_delete(mem, unpacked.str);
}

TEST(BinPack, EmptyBinCanBePackedAndUnpacked)
{
    const Memory *mem = os_memory();

    std::array<std::uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) {
            uint8_t dummy = 0;
            return bin_pack_bin(bp, &dummy, 0);
        },
        nullptr, nullptr, buf.data(), buf.size()));

    struct {
        uint8_t *data;
        uint32_t len;
    } unpacked = {reinterpret_cast<uint8_t *>(1),
        1};  // Initialize with non-null to check it gets set to null

    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<decltype(unpacked) *>(obj);
            return bin_unpack_bin(bu, &res->data, &res->len);
        },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked.len, 0);
    EXPECT_EQ(unpacked.data, nullptr);
}

TEST(BinPack, NullStringWithZeroLengthCanBePackedAndUnpacked)
{
    const Memory *mem = os_memory();

    std::array<std::uint8_t, 1> buf;
    EXPECT_TRUE(bin_pack_obj([](const void *obj, const Logger *logger,
                                 Bin_Pack *bp) { return bin_pack_str(bp, nullptr, 0); },
        nullptr, nullptr, buf.data(), buf.size()));

    struct {
        char *str;
        uint32_t len;
    } unpacked = {nullptr, 0};

    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<decltype(unpacked) *>(obj);
            return bin_unpack_str(bu, &res->str, &res->len);
        },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked.len, 0);
    ASSERT_NE(unpacked.str, nullptr);
    EXPECT_EQ(unpacked.str[0], '\0');
    mem_delete(mem, unpacked.str);
}

TEST(BinPack, NullBinWithZeroLengthCanBePackedAndUnpacked)
{
    const Memory *mem = os_memory();

    std::array<std::uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj([](const void *obj, const Logger *logger,
                                 Bin_Pack *bp) { return bin_pack_bin(bp, nullptr, 0); },
        nullptr, nullptr, buf.data(), buf.size()));

    struct {
        uint8_t *data;
        uint32_t len;
    } unpacked = {reinterpret_cast<uint8_t *>(1), 1};

    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<decltype(unpacked) *>(obj);
            return bin_unpack_bin(bu, &res->data, &res->len);
        },
        &unpacked, buf.data(), buf.size()));

    EXPECT_EQ(unpacked.len, 0);
    EXPECT_EQ(unpacked.data, nullptr);
}

TEST(BinPack, PackFailsWithNullAndNonZeroLength)
{
    std::array<std::uint8_t, 10> buf;
    // bin_pack_str
    EXPECT_FALSE(bin_pack_obj([](const void *obj, const Logger *logger,
                                  Bin_Pack *bp) { return bin_pack_str(bp, nullptr, 1); },
        nullptr, nullptr, buf.data(), buf.size()));

    // bin_pack_bin
    EXPECT_FALSE(bin_pack_obj([](const void *obj, const Logger *logger,
                                  Bin_Pack *bp) { return bin_pack_bin(bp, nullptr, 1); },
        nullptr, nullptr, buf.data(), buf.size()));

    // bin_pack_bin_b
    EXPECT_FALSE(bin_pack_obj([](const void *obj, const Logger *logger,
                                  Bin_Pack *bp) { return bin_pack_bin_b(bp, nullptr, 1); },
        nullptr, nullptr, buf.data(), buf.size()));
}

TEST(BinPack, PlainBinaryZeroLengthCanBePackedAndUnpacked)
{
    const Memory *mem = os_memory();

    std::array<std::uint8_t, 1> buf = {0xAA};  // Canary
    EXPECT_TRUE(bin_pack_obj([](const void *obj, const Logger *logger,
                                 Bin_Pack *bp) { return bin_pack_bin_b(bp, nullptr, 0); },
        nullptr, nullptr, buf.data(), buf.size()));

    // pos should not have advanced
    EXPECT_EQ(buf[0], 0xAA);

    std::uint8_t dummy = 0xBB;
    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            return bin_unpack_bin_b(bu, static_cast<std::uint8_t *>(obj), 0);
        },
        &dummy, buf.data(), 0));

    EXPECT_EQ(dummy, 0xBB);
}

TEST(BinPack, StringUnpackGuaranteesNonNull)
{
    const Memory *mem = os_memory();
    std::array<std::uint8_t, 1> buf;

    // Pack empty string
    bin_pack_obj(
        [](const void *obj, const Logger *logger, Bin_Pack *bp) { return bin_pack_str(bp, "", 0); },
        nullptr, nullptr, buf.data(), buf.size());

    char *res = nullptr;
    EXPECT_TRUE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto **ptr = static_cast<char **>(obj);
            uint32_t dummy_len;
            return bin_unpack_str(bu, ptr, &dummy_len);
        },
        &res, buf.data(), buf.size()));

    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res[0], '\0');
    mem_delete(mem, res);
}

TEST(BinPack, UnpackFailsOnBufferOverrun)
{
    const Memory *mem = os_memory();

    // 1. String claiming to be 100 bytes in a 5 byte buffer
    std::array<std::uint8_t, 5> buf;
    buf[0] = 0xD9;  // str 8
    buf[1] = 100;

    struct StrRes {
        char *s;
        uint32_t l;
    } res_str = {nullptr, 0};

    EXPECT_FALSE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<StrRes *>(obj);
            return bin_unpack_str(bu, &res->s, &res->l);
        },
        &res_str, buf.data(), buf.size()));

    // 2. Bin claiming to be 100 bytes
    buf[0] = 0xC4;  // bin 8
    buf[1] = 100;

    struct BinRes {
        uint8_t *b;
        uint32_t l;
    } res_bin = {nullptr, 0};

    EXPECT_FALSE(bin_unpack_obj(
        mem,
        [](void *obj, Bin_Unpack *bu) {
            auto *res = static_cast<BinRes *>(obj);
            return bin_unpack_bin(bu, &res->b, &res->l);
        },
        &res_bin, buf.data(), buf.size()));
}

}  // namespace
