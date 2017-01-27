#include <uds/client_channel_factory.h>

#include <errno.h>
#include <log/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <uds/channel_manager.h>
#include <uds/client_channel.h>
#include <uds/ipc_helper.h>

namespace android {
namespace pdx {
namespace uds {

std::string ClientChannelFactory::GetRootEndpointPath() {
  return "/dev/socket/pdx";
}

std::string ClientChannelFactory::GetEndpointPath(
    const std::string& endpoint_path) {
  std::string path;
  if (!endpoint_path.empty()) {
    if (endpoint_path.front() == '/')
      path = endpoint_path;
    else
      path = GetRootEndpointPath() + '/' + endpoint_path;
  }
  return path;
}

ClientChannelFactory::ClientChannelFactory(const std::string& endpoint_path)
    : endpoint_path_{GetEndpointPath(endpoint_path)} {}

std::unique_ptr<pdx::ClientChannelFactory> ClientChannelFactory::Create(
    const std::string& endpoint_path) {
  return std::unique_ptr<pdx::ClientChannelFactory>{
      new ClientChannelFactory{endpoint_path}};
}

Status<std::unique_ptr<pdx::ClientChannel>> ClientChannelFactory::Connect(
    int64_t timeout_ms) const {
  auto status = WaitForEndpoint(endpoint_path_, timeout_ms);
  if (!status)
    return ErrorStatus(status.error());

  LocalHandle socket_fd{socket(AF_UNIX, SOCK_STREAM, 0)};
  if (!socket_fd) {
    ALOGE("ClientChannelFactory::Connect: socket error %s", strerror(errno));
    return ErrorStatus(errno);
  }

  sockaddr_un remote;
  remote.sun_family = AF_UNIX;
  strncpy(remote.sun_path, endpoint_path_.c_str(), sizeof(remote.sun_path));
  remote.sun_path[sizeof(remote.sun_path) - 1] = '\0';

  int ret = RETRY_EINTR(connect(
      socket_fd.Get(), reinterpret_cast<sockaddr*>(&remote), sizeof(remote)));
  if (ret == -1) {
    ALOGE(
        "ClientChannelFactory::Connect: Failed to initialize connection when "
        "connecting %s",
        strerror(errno));
    return ErrorStatus(errno);
  }

  RequestHeader<BorrowedHandle> request;
  InitRequest(&request, opcodes::CHANNEL_OPEN, 0, 0, false);
  status = SendData(socket_fd.Get(), request);
  if (!status)
    return ErrorStatus(status.error());
  ResponseHeader<LocalHandle> response;
  status = ReceiveData(socket_fd.Get(), &response);
  if (!status)
    return ErrorStatus(status.error());
  int ref = response.ret_code;
  if (ref < 0 || static_cast<size_t>(ref) > response.file_descriptors.size())
    return ErrorStatus(EIO);

  LocalHandle event_fd = std::move(response.file_descriptors[ref]);
  return ClientChannel::Create(ChannelManager::Get().CreateHandle(
      std::move(socket_fd), std::move(event_fd)));
}

}  // namespace uds
}  // namespace pdx
}  // namespace android
