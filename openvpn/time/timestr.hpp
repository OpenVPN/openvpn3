//
//  timestr.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TIME_TIMESTR_H
#define OPENVPN_TIME_TIMESTR_H

#include <time.h>

#include <openvpn/common/types.hpp>

namespace openvpn {

  inline const char *date_time()
  {
    const time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char *ret = asctime(lt);
    const int len = strlen(ret);
    if (len > 0 && ret[len-1] == '\n')
      ret[len-1] = '\0';
    return ret;
  }
}

#endif
