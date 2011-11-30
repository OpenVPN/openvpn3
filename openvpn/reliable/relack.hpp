#ifndef OPENVPN_RELIABLE_RELACK_H
#define OPENVPN_RELIABLE_RELACK_H

#include <vector>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/reliable/relcommon.hpp>

namespace openvpn {

  class ReliableAck : public std::vector<ReliableMessageBase::id_t> // fixme -- make self contained
  {
  public:
  };

} // namespace openvpn

#endif // OPENVPN_RELIABLE_RELACK_H
