#ifndef OPENVPN_COMMON_DISPATCH_H
#define OPENVPN_COMMON_DISPATCH_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {
  // Dispatcher for asio async_read

  template <typename C, typename Handler, typename Data>
  class AsioDispatchRead
  {
  public:
    AsioDispatchRead(Handler handle_read, C* obj, Data data)
      : handle_read_(handle_read), obj_(obj), data_(data) {}

    void operator()(const boost::system::error_code& error, const size_t bytes_recvd)
    {
      (obj_.get()->*handle_read_)(data_, error, bytes_recvd);
    }

  private:
    Handler handle_read_;
    boost::intrusive_ptr<C> obj_;
    Data data_;
  };

  template <typename C, typename Handler, typename Data>
  AsioDispatchRead<C, Handler, Data> asio_dispatch_read(Handler handle_read, C* obj, Data data)
  {
    return AsioDispatchRead<C, Handler, Data>(handle_read, obj, data);
  }

  // Dispatcher for asio async_wait with argument

  template <typename C, typename Handler, typename Data>
  class AsioDispatchTimerArg
  {
  public:
    AsioDispatchTimerArg(Handler handler, C* obj, Data data)
      : handler_(handler), obj_(obj), data_(data) {}

    void operator()(const boost::system::error_code& error)
    {
      (obj_.get()->*handler_)(data_, error);
    }

  private:
    Handler handler_;
    boost::intrusive_ptr<C> obj_;
    Data data_;
  };

  template <typename C, typename Handler, typename Data>
  AsioDispatchTimerArg<C, Handler, Data> asio_dispatch_timer_arg(Handler handler, C* obj, Data data)
  {
    return AsioDispatchTimerArg<C, Handler, Data>(handler, obj, data);
  }

  // Dispatcher for asio async_wait without argument

  template <typename C, typename Handler>
  class AsioDispatchTimer
  {
  public:
    AsioDispatchTimer(Handler handler, C* obj)
      : handler_(handler), obj_(obj) {}

    void operator()(const boost::system::error_code& error)
    {
      (obj_.get()->*handler_)(error);
    }

  private:
    Handler handler_;
    boost::intrusive_ptr<C> obj_;
  };

  template <typename C, typename Handler>
  AsioDispatchTimer<C, Handler> asio_dispatch_timer(Handler handler, C* obj)
  {
    return AsioDispatchTimer<C, Handler>(handler, obj);
  }

  // Dispatcher for asynchronous resolver

  template <typename C, typename Handler, typename EndpointIterator>
  class AsioDispatchResolve
  {
  public:
    AsioDispatchResolve(Handler handler, C* obj)
      : handler_(handler), obj_(obj) {}

    void operator()(const boost::system::error_code& error, EndpointIterator iter)
    {
      (obj_.get()->*handler_)(error, iter);
    }

  private:
    Handler handler_;
    boost::intrusive_ptr<C> obj_;
  };

  // Dispatcher for asio signal

  template <typename C, typename Handler>
  class AsioDispatchSignal
  {
  public:
    AsioDispatchSignal(Handler handler, C* obj)
      : handler_(handler), obj_(obj) {}

    void operator()(const boost::system::error_code& error, int signal_number)
    {
      (obj_.get()->*handler_)(error, signal_number);
    }

  private:
    Handler handler_;
    boost::intrusive_ptr<C> obj_;
  };

  template <typename C, typename Handler>
  AsioDispatchSignal<C, Handler> asio_dispatch_signal(Handler handler, C* obj)
  {
    return AsioDispatchSignal<C, Handler>(handler, obj);
  }

  // General purpose dispatcher with data

  template <typename C, typename Handler, typename Data>
  class SimpleDispatch
  {
  public:
    SimpleDispatch(Handler handler, C* obj)
      : handler_(handler), obj_(obj) {}

    void operator()(Data data)
    {
      (obj_->*handler_)(data);
    }

  private:
    Handler handler_;
    C* obj_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_DISPATCH_H
