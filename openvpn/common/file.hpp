//
//  file.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Basic file-handling methods.

#ifndef OPENVPN_COMMON_FILE_H
#define OPENVPN_COMMON_FILE_H

#include <string>
#include <fstream>

#include <boost/cstdint.hpp> // for boost::uint64_t

#include <openvpn/common/exception.hpp>
#include <openvpn/common/unicode.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

  OPENVPN_UNTAGGED_EXCEPTION(file_exception);
  OPENVPN_UNTAGGED_EXCEPTION_INHERIT(file_exception, open_file_error);
  OPENVPN_UNTAGGED_EXCEPTION_INHERIT(file_exception, file_too_large);
  OPENVPN_UNTAGGED_EXCEPTION_INHERIT(file_exception, file_is_binary);
  OPENVPN_UNTAGGED_EXCEPTION_INHERIT(file_exception, file_not_utf8);

  // Read text from file via stream approach that doesn't require that we
  // establish the length of the file in advance.
  inline std::string read_text_simple(const std::string& filename)
  {
    std::ifstream ifs(filename.c_str());
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot open: " << filename);
    const std::string str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot read: " << filename);
    return str;
  }

  // Read a file (may be text or binary).
  inline BufferPtr read_binary(const std::string& filename,
			       const boost::uint64_t max_size = 0,
			       const unsigned int buffer_flags = 0)
  {
    std::ifstream ifs(filename.c_str(), std::ios::binary);
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot open: " << filename);

    // get length of file
    ifs.seekg (0, std::ios::end);
    const std::streamsize length = ifs.tellg();
    if (max_size && boost::uint64_t(length) > max_size)
      OPENVPN_THROW(file_too_large, "file too large [" << length << '/' << max_size << "]: " << filename);
    ifs.seekg (0, std::ios::beg);

    // allocate buffer
    BufferPtr b = new BufferAllocated(size_t(length), buffer_flags | BufferAllocated::ARRAY);

    // read data
    ifs.read((char *)b->data(), length);

    // check for errors
    if (ifs.gcount() != length)
      OPENVPN_THROW(open_file_error, "read length inconsistency: " << filename);
    if (!ifs)
      OPENVPN_THROW(open_file_error, "cannot read: " << filename);

    return b;
  }

  // Read a text file as a std::string, throw error if file is binary
  inline std::string read_text(const std::string& filename, const boost::uint64_t max_size = 0)
  {
    BufferPtr bp = read_binary(filename, max_size);
    if (bp->contains_null())
      OPENVPN_THROW(file_is_binary, "file is binary: " << filename);
    return std::string((const char *)bp->c_data(), bp->size());
  }

  // Read a UTF-8 file as a std::string, throw errors if file is binary or malformed UTF-8
  inline std::string read_text_utf8(const std::string& filename, const boost::uint64_t max_size = 0)
  {
    BufferPtr bp = read_binary(filename, max_size);
    if (bp->contains_null())
      OPENVPN_THROW(file_is_binary, "file is binary: " << filename);
    if (!Unicode::is_valid_utf8(bp->c_data(), bp->size()))
      OPENVPN_THROW(file_not_utf8, "file is not UTF8: " << filename);
    return std::string((const char *)bp->c_data(), bp->size());
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_FILE_H
