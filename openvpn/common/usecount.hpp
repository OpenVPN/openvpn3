//
//  usecount.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// General purpose class for scope accounting.

#ifndef OPENVPN_COMMON_USECOUNT_H
#define OPENVPN_COMMON_USECOUNT_H

namespace openvpn {

  class UseCount
  {
  public:
    UseCount(int& count)
      : count_(count)
    {
      ++count_;
    }

    ~UseCount()
    {
      --count_;
    }

  private:
    int& count_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_USECOUNT_H
