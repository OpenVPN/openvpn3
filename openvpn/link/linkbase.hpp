#ifndef OPENVPN_LINK_LINKBASE_H
#define OPENVPN_LINK_LINKBASE_H

#include <openvpn/common/bidir.hpp>

namespace openvpn {

  struct LinkParentBase
  {
  };

  struct LinkBase : public BidirObjBase<LinkParentBase, LinkBase>
  {
  };

} // namespace openvpn

#endif // OPENVPN_LINK_LINKBASE_H
