#include <gmock/gmock.h>
#include <gralloc_mock.h>
#include <gtest/gtest.h>
#include <private/dvr/ion_buffer.h>

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using android::dvr::IonBuffer;

GrallocMock* GrallocMock::staticObject = nullptr;

namespace {

const int w1 = 100;
const int h1 = 200;
const int d1 = 2;
const int f1 = 1;
const int u1 = 3;
const int stride1 = 8;
const int layer_stride1 = 8;
native_handle_t handle1;
const int w2 = 150;
const int h2 = 300;
const int d2 = 4;
const int f2 = 2;
const int u2 = 5;
const int stride2 = 4;
const int layer_stride2 = 4;
native_handle_t handle2;
const int kMaxFd = 10;
const int kMaxInt = 10;
char handleData[sizeof(native_handle_t) + (kMaxFd + kMaxInt) * sizeof(int)];
native_handle_t* const dataHandle =
    reinterpret_cast<native_handle_t*>(handleData);
char refData[sizeof(native_handle_t) + (kMaxFd + kMaxInt) * sizeof(int)];
native_handle_t* const refHandle = reinterpret_cast<native_handle_t*>(refData);

class IonBufferUnitTest : public ::testing::Test {
 protected:
  // You can remove any or all of the following functions if its body
  // is empty.

  IonBufferUnitTest() {
    GrallocMock::staticObject = new GrallocMock;
    // You can do set-up work for each test here.
    // most ServicefsClients will use this initializer. Use as the
    // default.
  }

  virtual ~IonBufferUnitTest() {
    delete GrallocMock::staticObject;
    GrallocMock::staticObject = nullptr;
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  void SetUp() override {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  void TearDown() override {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }
};

void TestIonBufferState(const IonBuffer& buffer, int w, int h, int d, int f,
                        int u, native_handle_t* handle, int stride,
                        int layer_stride) {
  EXPECT_EQ(buffer.width(), w);
  EXPECT_EQ(buffer.height(), h);
  EXPECT_EQ(buffer.layer_count(), d);
  EXPECT_EQ(buffer.format(), f);
  EXPECT_EQ(buffer.usage(), u);
  EXPECT_EQ(buffer.handle(), handle);
  EXPECT_EQ(buffer.stride(), stride);
  EXPECT_EQ(buffer.layer_stride(), layer_stride);
}

TEST_F(IonBufferUnitTest, TestFreeOnDestruction) {
  // Set up |alloc|(|w1...|) to succeed once and fail on others calls.
  EXPECT_CALL(*GrallocMock::staticObject, alloc(w1, h1, f1, u1, _, _))
      .Times(1)
      .WillOnce(DoAll(SetArgPointee<4>(&handle1), SetArgPointee<5>(stride1),
                      Return(0)));
  // Set up |free| to be called once.
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle1))
      .Times(1)
      .WillRepeatedly(Return(0));

  IonBuffer buffer;
  // First call to |alloc| with |w1...| set up to succeed.
  int ret = buffer.Alloc(w1, h1, f1, u1);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, &handle1, stride1, 0);

  // Scoped destructor will be called, calling |free| on |handle1|.
}

TEST_F(IonBufferUnitTest, TestAlloc) {
  IonBuffer buffer;
  // Set up |alloc|(|w1...|) to succeed once and fail on others calls.
  EXPECT_CALL(*GrallocMock::staticObject, alloc(w1, h1, f1, u1, _, _))
      .Times(2)
      .WillOnce(DoAll(SetArgPointee<4>(&handle1), SetArgPointee<5>(stride1),
                      Return(0)))
      .WillRepeatedly(Return(-1));

  // Set up |alloc|(|w2...|)  to succeed once and fail on others calls.
  EXPECT_CALL(*GrallocMock::staticObject, alloc(w2, h2, f2, u2, _, _))
      .Times(2)
      .WillOnce(DoAll(SetArgPointee<4>(&handle2), SetArgPointee<5>(stride2),
                      Return(0)))
      .WillRepeatedly(Return(-1));
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle1))
      .Times(1)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle2))
      .Times(1)
      .WillRepeatedly(Return(0));

  // First call to |alloc| with |w1...| set up to succeed.
  int ret = buffer.Alloc(w1, h1, f1, u1);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, &handle1, stride1, 0);

  // First call to |alloc| with |w2...| set up to succeed, |free| should be
  // called once on |handle1|.
  ret = buffer.Alloc(w2, h2, f2, u2);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w2, h2, 1, f2, u2, &handle2, stride2, 0);

  // Second call to |alloc| with |w1| is set up to fail.
  ret = buffer.Alloc(w1, h1, f1, u1);
  EXPECT_LT(ret, 0);
  TestIonBufferState(buffer, w2, h2, 1, f2, u2, &handle2, stride2, 0);

  // |free| on |handle2| should be called here.
  buffer.FreeHandle();
  TestIonBufferState(buffer, 0, 0, 0, 0, 0, nullptr, 0, 0);

  // |alloc| is set up to fail.
  ret = buffer.Alloc(w2, h2, f2, u2);
  EXPECT_LT(ret, 0);
  TestIonBufferState(buffer, 0, 0, 0, 0, 0, nullptr, 0, 0);
}

TEST_F(IonBufferUnitTest, TestReset) {
  IonBuffer buffer;
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle1))
      .Times(1)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle2))
      .Times(1)
      .WillRepeatedly(Return(0));
  buffer.Reset(&handle1, w1, h1, stride1, f1, u1);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, &handle1, stride1, 0);
  buffer.Reset(&handle2, w2, h2, stride2, f2, u2);
  TestIonBufferState(buffer, w2, h2, 1, f2, u2, &handle2, stride2, 0);
  buffer.FreeHandle();
}

TEST_F(IonBufferUnitTest, TestImport1) {
  IonBuffer buffer;
  EXPECT_CALL(*GrallocMock::staticObject, registerBuffer(&handle1))
      .Times(3)
      .WillOnce(Return(0))
      .WillRepeatedly(Return(-1));
  EXPECT_CALL(*GrallocMock::staticObject, registerBuffer(&handle2))
      .Times(3)
      .WillOnce(Return(0))
      .WillOnce(Return(-1))
      .WillOnce(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, unregisterBuffer(&handle1))
      .Times(1)
      .WillOnce(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_close(&handle1))
      .Times(1);
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_delete(&handle1))
      .Times(1);
  EXPECT_CALL(*GrallocMock::staticObject, alloc(w1, h1, f1, u1, _, _))
      .Times(1)
      .WillRepeatedly(DoAll(SetArgPointee<4>(&handle1),
                            SetArgPointee<5>(stride1), Return(0)));
  EXPECT_CALL(*GrallocMock::staticObject, unregisterBuffer(&handle2))
      .Times(2)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_close(&handle2))
      .Times(2);
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_delete(&handle2))
      .Times(2);
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle1))
      .Times(1)
      .WillRepeatedly(Return(0));

  int ret = buffer.Import(&handle1, w1, h1, stride1, f1, u1);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, &handle1, stride1, 0);
  ret = buffer.Import(&handle2, w2, h2, stride2, f2, u2);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w2, h2, 1, f2, u2, &handle2, stride2, 0);
  ret = buffer.Alloc(w1, h1, f1, u1);
  EXPECT_EQ(ret, 0);
  ret = buffer.Import(&handle2, w2, h2, stride2, f2, u2);
  EXPECT_LT(ret, 0);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, &handle1, stride1, 0);
  ret = buffer.Import(&handle2, w2, h2, stride2, f2, u2);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w2, h2, 1, f2, u2, &handle2, stride2, 0);
  ret = buffer.Import(&handle1, w1, h1, stride1, f1, u1);
  EXPECT_LT(ret, 0);
  TestIonBufferState(buffer, w2, h2, 1, f2, u2, &handle2, stride2, 0);
  buffer.FreeHandle();
  ret = buffer.Import(&handle1, w1, h1, stride1, f1, u1);
  EXPECT_LT(ret, 0);
  TestIonBufferState(buffer, 0, 0, 0, 0, 0, nullptr, 0, 0);
}

native_handle_t* native_handle_create_impl(int nFds, int nInts) {
  if ((nFds + nInts) > (kMaxFd + kMaxInt))
    return nullptr;
  dataHandle->version = sizeof(native_handle_t);
  dataHandle->numFds = nFds;
  dataHandle->numInts = nInts;
  for (int i = 0; i < nFds + nInts; i++)
    dataHandle->data[i] = 0;
  return dataHandle;
}

TEST_F(IonBufferUnitTest, TestImport2) {
  IonBuffer buffer;
  int ints[] = {211, 313, 444};
  int fds[] = {-1, -1};
  int ni = sizeof(ints) / sizeof(ints[0]);
  int nfd = sizeof(fds) / sizeof(fds[0]);
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_create(nfd, ni))
      .Times(3)
      .WillOnce(Return(nullptr))
      .WillRepeatedly(Invoke(native_handle_create_impl));
  EXPECT_CALL(*GrallocMock::staticObject, registerBuffer(dataHandle))
      .Times(2)
      .WillOnce(Return(-1))
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_close(dataHandle))
      .Times(2);
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_delete(dataHandle))
      .Times(2);
  EXPECT_CALL(*GrallocMock::staticObject, unregisterBuffer(dataHandle))
      .Times(1)
      .WillRepeatedly(Return(0));

  int ret = buffer.Import(fds, -1, ints, ni, w1, h1, stride1, f1, u1);
  EXPECT_LT(ret, 0);
  ret = buffer.Import(fds, nfd, ints, -1, w1, h1, stride1, f1, u1);
  EXPECT_LT(ret, 0);
  ret = buffer.Import(fds, nfd, ints, ni, w1, h1, stride1, f1, u1);
  EXPECT_LT(ret, 0);
  ret = buffer.Import(fds, nfd, ints, ni, w1, h1, stride1, f1, u1);
  EXPECT_LT(ret, 0);
  ret = buffer.Import(fds, nfd, ints, ni, w1, h1, stride1, f1, u1);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, dataHandle, stride1, 0);
  EXPECT_EQ(dataHandle->numFds, nfd);
  EXPECT_EQ(dataHandle->numInts, ni);
  for (int i = 0; i < nfd; i++)
    EXPECT_EQ(dataHandle->data[i], fds[i]);
  for (int i = 0; i < ni; i++)
    EXPECT_EQ(dataHandle->data[nfd + i], ints[i]);
  buffer.FreeHandle();
}

TEST_F(IonBufferUnitTest, TestDuplicate) {
  IonBuffer buffer;
  IonBuffer ref;
  int ints[] = {211, 313, 444};
  int fds[] = {-1, -1};
  int ni = sizeof(ints) / sizeof(ints[0]);
  int nfd = sizeof(fds) / sizeof(fds[0]);

  for (int i = 0; i < nfd; i++) {
    refHandle->data[i] = fds[i];
  }
  for (int i = 0; i < ni; i++) {
    refHandle->data[i + nfd] = ints[i];
  }

  EXPECT_CALL(*GrallocMock::staticObject, alloc(w1, h1, f1, u1, _, _))
      .Times(1)
      .WillRepeatedly(DoAll(SetArgPointee<4>(refHandle),
                            SetArgPointee<5>(stride1), Return(0)));
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_create(nfd, ni))
      .Times(3)
      .WillOnce(Return(nullptr))
      .WillRepeatedly(Invoke(native_handle_create_impl));
  EXPECT_CALL(*GrallocMock::staticObject, registerBuffer(dataHandle))
      .Times(2)
      .WillOnce(Return(-1))
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_close(dataHandle))
      .Times(2);
  EXPECT_CALL(*GrallocMock::staticObject, native_handle_delete(dataHandle))
      .Times(2);
  EXPECT_CALL(*GrallocMock::staticObject, unregisterBuffer(dataHandle))
      .Times(1)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(*GrallocMock::staticObject, free(refHandle))
      .Times(1)
      .WillRepeatedly(Return(0));

  int ret = buffer.Duplicate(&ref);
  EXPECT_LT(ret, 0);
  ret = ref.Alloc(w1, h1, f1, u1);
  EXPECT_EQ(ret, 0);
  refHandle->numFds = -1;
  refHandle->numInts = 0;
  ret = buffer.Duplicate(&ref);
  EXPECT_LT(ret, 0);
  refHandle->numFds = nfd;
  refHandle->numInts = ni;
  ret = buffer.Duplicate(&ref);
  EXPECT_LT(ret, 0);
  ret = buffer.Duplicate(&ref);
  EXPECT_LT(ret, 0);
  ret = buffer.Duplicate(&ref);
  EXPECT_EQ(ret, 0);
  TestIonBufferState(buffer, w1, h1, 1, f1, u1, dataHandle, stride1, 0);
  EXPECT_EQ(dataHandle->numFds, nfd);
  EXPECT_EQ(dataHandle->numInts, ni);
  for (int i = 0; i < nfd; i++)
    EXPECT_LT(dataHandle->data[i], 0);
  for (int i = 0; i < ni; i++)
    EXPECT_EQ(dataHandle->data[nfd + i], ints[i]);
  buffer.FreeHandle();
  ref.FreeHandle();
}

TEST_F(IonBufferUnitTest, TestLockUnlock) {
  IonBuffer buffer;
  const int x = 12;
  const int y = 24;
  const int value1 = 17;
  const int value2 = 25;
  void* addr1;
  void** addr = &addr1;

  EXPECT_CALL(*GrallocMock::staticObject, alloc(w1, h1, f1, u1, _, _))
      .Times(1)
      .WillRepeatedly(DoAll(SetArgPointee<4>(&handle1),
                            SetArgPointee<5>(stride1), Return(0)));
  EXPECT_CALL(*GrallocMock::staticObject,
              lock(&handle1, u2, x, y, w2, h2, addr))
      .Times(1)
      .WillRepeatedly(Return(value1));
  EXPECT_CALL(*GrallocMock::staticObject, unlock(&handle1))
      .Times(1)
      .WillRepeatedly(Return(value2));
  EXPECT_CALL(*GrallocMock::staticObject, free(&handle1))
      .Times(1)
      .WillRepeatedly(Return(0));

  int ret = buffer.Alloc(w1, h1, f1, u1);
  EXPECT_EQ(ret, 0);
  ret = buffer.Lock(u2, x, y, w2, h2, addr);
  EXPECT_EQ(ret, value1);
  ret = buffer.Unlock();
  EXPECT_EQ(ret, value2);
  buffer.FreeHandle();
}

}  // namespace
