//
//  proto_context_options.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_SSL_PROTO_CONTEXT_OPTIONS_H
#define OPENVPN_SSL_PROTO_CONTEXT_OPTIONS_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {
  struct ProtoContextOptions : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<ProtoContextOptions> Ptr;

    enum CompressionMode {
      COMPRESS_NO,
      COMPRESS_YES,
      COMPRESS_ASYM
    };

    ProtoContextOptions() : compression_mode(COMPRESS_NO) {}

    bool is_comp() const { return compression_mode != COMPRESS_NO; }
    bool is_comp_asym() const { return compression_mode == COMPRESS_ASYM; }

    void parse_compression_mode(const std::string& mode)
    {
      if (mode == "no")
	compression_mode = COMPRESS_NO;
      else if (mode == "yes")
	compression_mode = COMPRESS_YES;
      else if (mode == "asym")
	compression_mode = COMPRESS_ASYM;
      else
	OPENVPN_THROW(option_error, "error parsing compression mode: " << mode);
    }

    CompressionMode compression_mode;
  };
}

#endif
