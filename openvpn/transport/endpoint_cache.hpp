#ifndef OPENVPN_TRANSPORT_ENDPOINT_CACHE_H
#define OPENVPN_TRANSPORT_ENDPOINT_CACHE_H

#include <openvpn/common/exception.hpp>

namespace openvpn {

  template <typename EP>
  class EndpointCache
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(endpoint_cache_undefined);

    EndpointCache() : defined_(false) {}

    void reset()
    {
      defined_ = false;
    }

    void set_endpoint(const EP& endpoint)
      {
	defined_ = true;
	endpoint_ = endpoint;
      }

    bool defined() const
    {
      return defined_;
    }

    const EP& endpoint() const
    {
      if (!defined_)
	throw endpoint_cache_undefined();
      return endpoint_;
    }

  private:
    bool defined_;
    EP endpoint_;
  };

} // namespace openvpn

#endif // OPENVPN_TRANSPORT_ENDPOINT_CACHE_H
