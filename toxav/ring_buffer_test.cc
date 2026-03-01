#include "ring_buffer.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

#include "../toxcore/attributes.h"

namespace {

template <typename T>
class TypedRingBuffer;

template <typename T>
class TypedRingBuffer<T *> {
public:
    explicit TypedRingBuffer(int size)
        : rb_(rb_new(size))
    {
    }
    ~TypedRingBuffer() { rb_kill(rb_); }
    TypedRingBuffer(TypedRingBuffer const &) = delete;

    bool full() const { return rb_full(rb_); }
    bool empty() const { return rb_empty(rb_); }
    T *_Nullable write(T *_Nullable p) { return static_cast<T *>(rb_write(rb_, p)); }
    bool read(T *_Nullable *_Nonnull p)
    {
        void *_Nullable vp;
        bool res = rb_read(rb_, &vp);
        *p = static_cast<T *>(vp);
        return res;
    }

    std::uint16_t size() const { return rb_size(rb_); }
    std::uint16_t data(T *_Nullable *_Nonnull dest, std::uint16_t dest_size) const
    {
        const std::uint16_t current_size = std::min(size(), dest_size);
        std::vector<void *_Nullable> vdest(current_size);
        const std::uint16_t res = rb_data(rb_, vdest.data(), current_size);
        for (std::uint16_t i = 0; i < res; i++) {
            dest[i] = static_cast<T *>(vdest.at(i));
        }
        return res;
    }

    bool contains(T *_Nullable p) const
    {
        const std::uint16_t current_size = size();
        std::vector<T *_Nullable> elts(current_size);
        data(elts.data(), current_size);
        return std::find(elts.begin(), elts.end(), p) != elts.end();
    }

    bool ok() const { return rb_ != nullptr; }

private:
    RingBuffer *_Nullable rb_;
};

TEST(RingBuffer, EmptyBufferReportsEmpty)
{
    TypedRingBuffer<int *> rb(10);
    ASSERT_TRUE(rb.ok());
    EXPECT_TRUE(rb.empty());
}

TEST(RingBuffer, EmptyBufferReportsNotFull)
{
    TypedRingBuffer<int *> rb(10);
    ASSERT_TRUE(rb.ok());
    EXPECT_FALSE(rb.full());
}

TEST(RingBuffer, ZeroSizedRingBufferIsBothEmptyAndFull)
{
    TypedRingBuffer<int *> rb(0);
    ASSERT_TRUE(rb.ok());
    EXPECT_TRUE(rb.empty());
    EXPECT_TRUE(rb.full());
}

TEST(RingBuffer, WritingMakesBufferNotEmpty)
{
    TypedRingBuffer<int *> rb(2);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    rb.write(&value0);
    EXPECT_FALSE(rb.empty());
}

TEST(RingBuffer, WritingOneElementMakesBufferNotFull)
{
    TypedRingBuffer<int *> rb(2);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    rb.write(&value0);
    EXPECT_FALSE(rb.full());
}

TEST(RingBuffer, WritingAllElementsMakesBufferFull)
{
    TypedRingBuffer<int *> rb(2);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    int value1 = 231;
    rb.write(&value0);
    rb.write(&value1);
    EXPECT_TRUE(rb.full());
}

TEST(RingBuffer, ReadingElementFromFullBufferMakesItNotFull)
{
    TypedRingBuffer<int *> rb(2);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    int value1 = 231;
    rb.write(&value0);
    rb.write(&value1);
    EXPECT_TRUE(rb.full());
    int *retrieved;
    // Reading deletes the element.
    EXPECT_TRUE(rb.read(&retrieved));
    EXPECT_FALSE(rb.full());
}

TEST(RingBuffer, ZeroSizeBufferCanBeWrittenToOnce)
{
    TypedRingBuffer<int *> rb(0);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    // Strange behaviour: we can write one element to a 0-size buffer.
    EXPECT_EQ(nullptr, rb.write(&value0));
    EXPECT_EQ(&value0, rb.write(&value0));
    int *retrieved = nullptr;
    // But then we can't read it.
    EXPECT_FALSE(rb.read(&retrieved));
    EXPECT_EQ(nullptr, retrieved);
}

TEST(RingBuffer, ReadingFromEmptyBufferFails)
{
    TypedRingBuffer<int *> rb(2);
    ASSERT_TRUE(rb.ok());
    int *retrieved;
    EXPECT_FALSE(rb.read(&retrieved));
}

TEST(RingBuffer, WritingToBufferWhenFullOverwritesBeginning)
{
    TypedRingBuffer<int *> rb(2);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    int value1 = 231;
    int value2 = 312;
    int value3 = 432;
    EXPECT_EQ(nullptr, rb.write(&value0));
    EXPECT_EQ(nullptr, rb.write(&value1));
    EXPECT_TRUE(rb.contains(&value0));
    EXPECT_TRUE(rb.contains(&value1));

    // Adding another element evicts the first element.
    EXPECT_EQ(&value0, rb.write(&value2));
    EXPECT_FALSE(rb.contains(&value0));
    EXPECT_TRUE(rb.contains(&value2));

    // Adding another evicts the second.
    EXPECT_EQ(&value1, rb.write(&value3));
    EXPECT_FALSE(rb.contains(&value1));
    EXPECT_TRUE(rb.contains(&value3));
}

TEST(RingBuffer, SizeIsNumberOfElementsInBuffer)
{
    TypedRingBuffer<int *> rb(10);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    EXPECT_EQ(rb.size(), 0);
    rb.write(&value0);
    EXPECT_EQ(rb.size(), 1);
    rb.write(&value0);
    EXPECT_EQ(rb.size(), 2);
    rb.write(&value0);
    EXPECT_EQ(rb.size(), 3);
    rb.write(&value0);
    EXPECT_EQ(rb.size(), 4);

    int *retrieved;
    rb.read(&retrieved);
    EXPECT_EQ(rb.size(), 3);
    rb.read(&retrieved);
    EXPECT_EQ(rb.size(), 2);
    rb.read(&retrieved);
    EXPECT_EQ(rb.size(), 1);
    rb.read(&retrieved);
    EXPECT_EQ(rb.size(), 0);
}

TEST(RingBuffer, SizeIsLimitedByMaxSize)
{
    TypedRingBuffer<int *> rb(4);
    ASSERT_TRUE(rb.ok());
    int value0 = 123;
    rb.write(&value0);
    rb.write(&value0);
    rb.write(&value0);
    rb.write(&value0);
    EXPECT_EQ(rb.size(), 4);

    // Add one more.
    rb.write(&value0);
    // Still size is 4.
    EXPECT_EQ(rb.size(), 4);
}

TEST(RingBuffer, NewWithInvalidSizeReturnsNull)
{
    EXPECT_EQ(nullptr, rb_new(-1));
    EXPECT_EQ(nullptr, rb_new(65535));
}

TEST(RingBuffer, DataWithSmallerDestSizeIsTruncated)
{
    TypedRingBuffer<int *> rb(4);
    ASSERT_TRUE(rb.ok());
    int values[] = {1, 2, 3, 4};
    rb.write(&values[0]);
    rb.write(&values[1]);
    rb.write(&values[2]);
    rb.write(&values[3]);

    int *dest[2];
    std::uint16_t res = rb.data(dest, 2);
    EXPECT_EQ(res, 2);
    EXPECT_EQ(dest[0], &values[0]);
    EXPECT_EQ(dest[1], &values[1]);
}

}  // namespace
