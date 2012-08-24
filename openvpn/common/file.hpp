//
//  file.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_FILE_H
#define OPENVPN_COMMON_FILE_H

#include <string>
#include <fstream>

#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(open_file_error);

  inline std::string read_text(const std::string& filename)
  {
    std::ifstream ifs(filename.c_str());
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot open " << filename);
    const std::string str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot read " << filename);
    return str;
  }

  inline BufferPtr read_binary(const std::string& filename, const unsigned int buffer_flags = 0)
  {
    std::ifstream ifs(filename.c_str(), std::ios::binary);
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot open " << filename);

    // get length of file
    ifs.seekg (0, std::ios::end);
    const std::streamsize length = ifs.tellg();
    ifs.seekg (0, std::ios::beg);

    // allocate buffer
    BufferPtr b = new BufferAllocated(size_t(length), buffer_flags | BufferAllocated::ARRAY);

    // read data
    ifs.read((char *)b->data(), length);

    // check for errors
    if (ifs.gcount() != length)
      OPENVPN_THROW(open_file_error, "read length inconsistency " << filename);
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot read " << filename);

    return b;
  }

  inline std::string read_text_fast(const std::string& filename)
  {
    BufferPtr bp = read_binary(filename);
    return std::string((const char *)bp->c_data(), bp->size());
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_FILE_H
