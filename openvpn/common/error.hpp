#ifndef OPENVPN_COMMON_ERROR_H
#define OPENVPN_COMMON_ERROR_H

#include <openssl/err.h>
#include <boost/exception/all.hpp>

namespace openvpn {

typedef boost::error_info<struct errinfo_general_,char const *> errinfo_general;

} // namespace openvpn

#endif // OPENVPN_COMMON_ERROR_H
