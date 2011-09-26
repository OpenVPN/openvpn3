#ifndef OPENVPN_COMMON_DISPATCH_H
#define OPENVPN_COMMON_DISPATCH_H

namespace openvpn {

  template <typename C, typename Handler, typename Data>
  class AsioDispatchRead
  {
  public:
    AsioDispatchRead(Handler handle_read, C* obj, Data data)
      : handle_read_(handle_read), obj_(obj), data_(data) {}

    void operator()(const boost::system::error_code& error, const size_t bytes_recvd)
    {
      (obj_->*handle_read_)(data_, error, bytes_recvd);
    }

  private:
    Handler handle_read_;
    C *obj_;
    Data data_;
  };

  template <typename C, typename Handler, typename Data>
  AsioDispatchRead<C, Handler, Data> asio_dispatch_read(Handler handle_read, C* obj, Data data)
  {
    return AsioDispatchRead<C, Handler, Data>(handle_read, obj, data);
  }

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
    C *obj_;
  };
} // namespace openvpn

#endif // OPENVPN_COMMON_DISPATCH_H
