#ifndef OPENVPN_COMMON_FILE_H
#define OPENVPN_COMMON_FILE_H

#include <string>
#include <fstream>

#include <openvpn/common/exception.hpp>

OPENVPN_EXCEPTION(open_file_error);

namespace openvpn {

  std::string read_text(const char *filename)
  {
    std::ifstream ifs(filename);
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot open " << filename);
    const std::string str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return str;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_FILE_H
