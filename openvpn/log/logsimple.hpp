#ifndef OPENVPN_LOG_LOGSIMPLE_H
#define OPENVPN_LOG_LOGSIMPLE_H

#include <iostream>

#define OPENVPN_LOG(args) std::cout << args << std::endl

// like OPENVPN_LOG but no trailing newline
#define OPENVPN_LOG_NTNL(args) std::cout << args

#endif // OPENVPN_LOG_LOGSIMPLE_H
