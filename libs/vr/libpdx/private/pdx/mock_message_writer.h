#ifndef ANDROID_PDX_MOCK_MESSAGE_WRITER_H_
#define ANDROID_PDX_MOCK_MESSAGE_WRITER_H_

#include <gmock/gmock.h>
#include <pdx/message_writer.h>

namespace android {
namespace pdx {

class MockOutputResourceMapper : public OutputResourceMapper {
 public:
  MOCK_METHOD1(PushFileHandle, FileReference(const LocalHandle& handle));
  MOCK_METHOD1(PushFileHandle, FileReference(const BorrowedHandle& handle));
  MOCK_METHOD1(PushFileHandle, FileReference(const RemoteHandle& handle));
  MOCK_METHOD1(PushChannelHandle,
               ChannelReference(const LocalChannelHandle& handle));
  MOCK_METHOD1(PushChannelHandle,
               ChannelReference(const BorrowedChannelHandle& handle));
  MOCK_METHOD1(PushChannelHandle,
               ChannelReference(const RemoteChannelHandle& handle));
};

class MockMessageWriter : public MessageWriter {
 public:
  MOCK_METHOD1(GetNextWriteBufferSection, void*(size_t size));
  MOCK_METHOD0(GetOutputResourceMapper, OutputResourceMapper*());
};

}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_MOCK_MESSAGE_WRITER_H_
