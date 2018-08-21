#include "ring_buffer.h"

#include <algorithm>
#include <cassert>
#include <vector>

#include <gtest/gtest.h>

namespace {

template <typename T>
class TypedRingBuffer;

template <typename T>
class TypedRingBuffer<T *> {
 public:
  explicit TypedRingBuffer(int size) : rb_(rb_new(size)) {}
  ~TypedRingBuffer() { rb_kill(rb_); }
  TypedRingBuffer(TypedRingBuffer const &) = delete;

  bool full() const { return rb_full(rb_); }
  bool empty() const { return rb_empty(rb_); }
  T *write(T *p) { return static_cast<T *>(rb_write(rb_, p)); }
  bool read(T **p) {
    void *vp;
    bool res = rb_read(rb_, &vp);
    *p = static_cast<T *>(vp);
    return res;
  }

  uint16_t size() const { return rb_size(rb_); }
  uint16_t data(T **dest) const {
    std::vector<void *> vdest(size());
    uint16_t res = rb_data(rb_, vdest.data());
    for (uint16_t i = 0; i < size(); i++) {
      dest[i] = static_cast<T *>(vdest.at(i));
    }
    return res;
  }

  bool contains(T *p) const {
    std::vector<T *> elts(size());
    data(elts.data());
    return std::find(elts.begin(), elts.end(), p) != elts.end();
  }

  bool ok() const { return rb_ != nullptr; }

 private:
  RingBuffer *rb_;
};

TEST(RingBuffer, EmptyBufferReportsEmpty) {
  TypedRingBuffer<int *> rb(10);
  ASSERT_TRUE(rb.ok());
  EXPECT_TRUE(rb.empty());
}

TEST(RingBuffer, EmptyBufferReportsNotFull) {
  TypedRingBuffer<int *> rb(10);
  ASSERT_TRUE(rb.ok());
  EXPECT_FALSE(rb.full());
}

TEST(RingBuffer, ZeroSizedRingBufferIsBothEmptyAndFull) {
  TypedRingBuffer<int *> rb(0);
  ASSERT_TRUE(rb.ok());
  EXPECT_TRUE(rb.empty());
  EXPECT_TRUE(rb.full());
}

TEST(RingBuffer, WritingMakesBufferNotEmpty) {
  TypedRingBuffer<int *> rb(2);
  ASSERT_TRUE(rb.ok());
  int value0 = 123;
  rb.write(&value0);
  EXPECT_FALSE(rb.empty());
}

TEST(RingBuffer, WritingOneElementMakesBufferNotFull) {
  TypedRingBuffer<int *> rb(2);
  ASSERT_TRUE(rb.ok());
  int value0 = 123;
  rb.write(&value0);
  EXPECT_FALSE(rb.full());
}

TEST(RingBuffer, WritingAllElementsMakesBufferFull) {
  TypedRingBuffer<int *> rb(2);
  ASSERT_TRUE(rb.ok());
  int value0 = 123;
  int value1 = 231;
  rb.write(&value0);
  rb.write(&value1);
  EXPECT_TRUE(rb.full());
}

TEST(RingBuffer, ReadingElementFromFullBufferMakesItNotFull) {
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

TEST(RingBuffer, ZeroSizeBufferCanBeWrittenToOnce) {
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

TEST(RingBuffer, ReadingFromEmptyBufferFails) {
  TypedRingBuffer<int *> rb(2);
  ASSERT_TRUE(rb.ok());
  int *retrieved;
  EXPECT_FALSE(rb.read(&retrieved));
}

TEST(RingBuffer, WritingToBufferWhenFullOverwritesBeginning) {
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

TEST(RingBuffer, SizeIsNumberOfElementsInBuffer) {
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

TEST(RingBuffer, SizeIsLimitedByMaxSize) {
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

}  // namespace
