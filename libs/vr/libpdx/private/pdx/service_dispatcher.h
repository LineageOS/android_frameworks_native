#ifndef ANDROID_PDX_SERVICE_DISPATCHER_H_
#define ANDROID_PDX_SERVICE_DISPATCHER_H_

#include <memory>

namespace android {
namespace pdx {

class Service;

/*
 * ServiceDispatcher manages a list of Service instances and handles message
 * reception and dispatch to the services. This makes repetitive dispatch tasks
 * easier to implement.
 */
class ServiceDispatcher {
 public:
  virtual ~ServiceDispatcher() = default;

  /*
   * Adds a service to the list of services handled by this dispatcher. This
   * will fail if any threads are blocked waiting for messages in this
   * dispatcher.
   *
   * Returns 0 on success; -EEXIST if the service was already added.
   */
  virtual int AddService(const std::shared_ptr<Service>& service) = 0;

  /*
   * Removes a service from this dispatcher. This will fail if any threads are
   * blocked waiting for messages in this dispatcher.
   *
   * Returns 0 on success; -ENOENT if the service was not previously added;
   * -EBUSY if there are threads in the dispatcher.
   */
  virtual int RemoveService(const std::shared_ptr<Service>& service) = 0;

  /*
   * Receive and dispatch one set of messages. Multiple threads may enter this
   * method to create an implicit thread pool, as described for
   * enterDispatchLoop() below, however this method exits after one dispatch
   * cycle, requiring an external loop. This is useful when other work needs
   * to be done in the service dispatch loop.
   */
  virtual int ReceiveAndDispatch() = 0;

  /*
   * Same as above with timeout in milliseconds. A negative value means
   * infinite timeout, while a value of 0 means return immediately if no
   * messages are available to receive.
   */
  virtual int ReceiveAndDispatch(int timeout) = 0;

  /*
   * Receive and dispatch messages until canceled. When more than one thread
   * enters this method it creates an implicit thread pool to dispatch messages.
   * Explicit thread pools may be created by using a single dispatch thread that
   * hands Message instances (via move assignment) over to a queue of threads
   * (or perhaps one of several) to handle.
   */
  virtual int EnterDispatchLoop() = 0;

  /*
   * Sets the canceled state of the dispatcher. When canceled is true, any
   * threads blocked waiting for messages will return. This method waits until
   * all dispatch threads have exited the dispatcher.
   */
  virtual void SetCanceled(bool cancel) = 0;

  /*
   * Gets the canceled state of the dispatcher.
   */
  virtual bool IsCanceled() const = 0;
};

}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_SERVICE_DISPATCHER_H_
