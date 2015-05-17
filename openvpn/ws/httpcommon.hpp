//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

// HTTP code common to both clients and servers

#ifndef OPENVPN_WS_HTTPCOMMON_H
#define OPENVPN_WS_HTTPCOMMON_H

#include <string>
#include <memory>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/http/header.hpp>
#include <openvpn/http/status.hpp>
#include <openvpn/ssl/sslapi.hpp>
#include <openvpn/ssl/sslconsts.hpp>
#include <openvpn/ws/chunked.hpp>

namespace openvpn {
  namespace WS {
    OPENVPN_EXCEPTION(http_exception);

    template <typename PARENT,
	      typename CONFIG,
	      typename STATUS,
	      typename REQUEST_REPLY,
	      typename CONTENT_INFO,
	      typename CONTENT_LENGTH_TYPE
	      >
    class HTTPBase : public RC<thread_unsafe_refcount>
    {
      friend ChunkedHelper;

    public:
      void rr_reset()
      {
	rr_obj.reset();
	rr_status = REQUEST_REPLY::Parser::pending;
	rr_parser.reset();
	rr_header_bytes = 0;
	rr_content_length = 0;
	rr_content_bytes = 0;
	rr_chunked.reset();
	out_state = S_PRE;
      }

      void reset()
      {
	if (halt)
	  {
	    halt = false;
	    ready = true;
	  }
      }

      bool is_ready() const {
	return !halt && ready;
      }

      const typename REQUEST_REPLY::State& request_reply() const {
	return rr_obj;
      }

      const HTTP::HeaderList& headers() const {
	return rr_obj.headers;
      }

      const olong content_length() const {
	return rr_content_length;
      }

      std::string ssl_handshake_details() const {
	if (ssl_sess)
	  return ssl_sess->ssl_handshake_details();
	else
	  return "";
      }

    protected:
      HTTPBase(const typename CONFIG::Ptr& config_arg)
	: halt(false),
	  ready(true),
	  config(config_arg),
	  frame(config_arg->frame),
	  stats(config_arg->stats)
      {
	rr_reset();
      }

      void http_out_begin()
      {
	out_state = S_OUT;
      }

      // Transmit outgoing HTTP, either to SSL object (HTTPS) or TCP socket (HTTP)
      void http_out()
      {
	if (halt)
	  return;
	if (out_state == S_PRE)
	  {
	    if (ssl_sess)
	      ssl_down_stack();
	    return;
	  }
	if (out_state == S_OUT && (!outbuf || outbuf->empty()))
	  {
	    outbuf = parent().base_http_content_out();
	    if (!outbuf || !outbuf->defined())
	      out_state = S_EOF;
	    if (content_info.length == CONTENT_INFO::CHUNKED)
	      outbuf = ChunkedHelper::transmit(outbuf);
	  }
	if (outbuf)
	  {
	    const size_t size = std::min(outbuf->size(), http_buf_size());
	    if (size)
	      {
		if (ssl_sess)
		  {
		    // HTTPS: send outgoing cleartext HTTP data from request/reply to SSL object
		    ssize_t actual = 0;
		    try {
		      actual = ssl_sess->write_cleartext_unbuffered(outbuf->data(), size);
		    }
		    catch (...)
		      {
			stats->error(Error::SSL_ERROR);
			throw;
		      }
		    if (actual >= 0)
		      {
#if defined(OPENVPN_DEBUG_HTTP)
			BufferAllocated tmp(outbuf->c_data(), actual, 0);
			OPENVPN_LOG(buf_to_string(tmp));
#endif
			outbuf->advance(actual);
		      }
		    else if (actual == SSLConst::SHOULD_RETRY)
		      ;
		    else
		      throw http_exception("unknown write status from SSL layer");
		    ssl_down_stack();
		  }
		else
		  {
		    // HTTP: send outgoing cleartext HTTP data from request/reply to TCP socket
		    BufferAllocated buf;
		    frame->prepare(Frame::WRITE_HTTP, buf);
		    buf.write(outbuf->data(), size);
#if defined(OPENVPN_DEBUG_HTTP)
		    OPENVPN_LOG(buf_to_string(buf));
#endif
		    if (parent().base_link_send(buf))
		      outbuf->advance(size);
		  }
	      }
	  }
	if (out_state == S_EOF && parent().base_send_queue_empty())
	  {
	    out_state = S_DONE;
	    outbuf.reset();
	    parent().base_http_out_eof();
	  }
      }

      void tcp_in(BufferAllocated& b)
      {
	if (ssl_sess)
	  {
	    // HTTPS
	    BufferPtr buf(new BufferAllocated());
	    buf->swap(b); // take ownership
	    ssl_sess->write_ciphertext(buf);
	    ssl_up_stack();
	    ssl_down_stack();

	    // In some cases, such as immediately after handshake,
	    // a write becomes possible after a read has completed.
	    http_out();
	  }
	else
	  {
	    // HTTP
	    http_in(b);
	  }
      }

      // Callback methods in parent:
      //   BufferPtr base_http_content_out();
      //   void base_http_out_eof();
      //   bool base_http_headers_received();
      //   void base_http_content_in(BufferAllocated& buf);
      //   bool base_link_send(BufferAllocated& buf);
      //   bool base_send_queue_empty();
      //   void base_http_done_handler(BufferAllocated& residual)
      //   void base_error_handler(const int errcode, const std::string& err);

      // protected member vars

      bool halt;
      bool ready;

      typename CONFIG::Ptr config;
      CONTENT_INFO content_info;
      SSLAPI::Ptr ssl_sess;

      BufferPtr outbuf;

      Frame::Ptr frame;
      SessionStats::Ptr stats;

    private:
      PARENT& parent()
      {
	return *static_cast<PARENT*>(this);
      }

      void chunked_content_in(BufferAllocated& buf) // called by ChunkedHelper
      {
	do_http_content_in(buf);
      }

      void do_http_content_in(BufferAllocated& buf)
      {
	if (halt)
	  return;
	if (buf.defined())
	  {
	    rr_content_bytes += buf.size();
	    if (config->max_content_bytes && rr_content_bytes > config->max_content_bytes)
	      {
		parent().base_error_handler(STATUS::E_CONTENT_SIZE, "HTTP content too large");
		return;
	      }
	    parent().base_http_content_in(buf);
	  }
      }

      // Receive incoming HTTP
      void http_in(BufferAllocated& buf)
      {
	if (halt || ready) // if ready, indicates unsolicited input
	  return;

	if (rr_status == REQUEST_REPLY::Parser::pending)
	  {
	    // processing HTTP request/reply and headers
	    for (size_t i = 0; i < buf.size(); ++i)
	      {
		rr_status = rr_parser.consume(rr_obj, (char)buf[i]);
		if (rr_status == REQUEST_REPLY::Parser::pending)
		  {
		    ++rr_header_bytes;
		    if ((rr_header_bytes & 0x3F) == 0)
		      {
			// only check header maximums once every 64 bytes
			if ((config->max_header_bytes && rr_header_bytes > config->max_header_bytes)
			    || (config->max_headers && rr_obj.headers.size() > config->max_headers))
			  {
			    parent().base_error_handler(STATUS::E_HEADER_SIZE, "HTTP headers too large");
			    return;
			  }
		      }
		  }
		else
		  {
		    // finished processing HTTP request/reply and headers
		    buf.advance(i+1);
		    if (rr_status == REQUEST_REPLY::Parser::success)
		      {
			rr_content_length = get_content_length(rr_obj.headers);
			if (rr_content_length == CONTENT_INFO::CHUNKED)
			  rr_chunked.reset(new ChunkedHelper());
			if (!parent().base_http_headers_received())
			  {
			    // parent wants to handle content itself,
			    // pass post-header residual data
			    parent().base_http_done_handler(buf);
			    return;
			  }
			break;
		      }
		    else
		      {
			parent().base_error_handler(STATUS::E_HTTP, "HTTP headers parse error");
			return;
		      }
		  }
	      }
	  }

	if (rr_status == REQUEST_REPLY::Parser::success)
	  {
	    // processing HTTP content
	    bool done = false;
	    if (rr_content_length >= 0)
	      {
		const CONTENT_LENGTH_TYPE needed = std::max(rr_content_length - rr_content_bytes, CONTENT_LENGTH_TYPE(0));
		if (needed <= buf.size())
		  {
		    done = true;
		    if (needed < buf.size())
		      buf.set_size(needed); // drop post-content residual data
		  }
		do_http_content_in(buf);
	      }
	    else if (rr_chunked)
	      {
		done = rr_chunked->receive(*this, buf);
	      }
	    if (done)
	      {
		BufferAllocated empty;
		parent().base_http_done_handler(empty);
	      }
	  }
      }

      // read outgoing ciphertext data from SSL object and xmit to TCP socket
      void ssl_down_stack()
      {
	while (!halt && ssl_sess->read_ciphertext_ready())
	  {
	    BufferPtr buf = ssl_sess->read_ciphertext();
	    parent().base_link_send(*buf);
	  }
      }

      // read incoming cleartext data from SSL object and pass to HTTP receiver
      void ssl_up_stack()
      {
	BufferAllocated buf;
	while (!halt && ssl_sess->read_cleartext_ready())
	  {
	    frame->prepare(Frame::READ_SSL_CLEARTEXT, buf);
	    ssize_t size = 0;
	    try {
	      size = ssl_sess->read_cleartext(buf.data(), buf.max_size());
	    }
	    catch (...)
	      {
		stats->error(Error::SSL_ERROR);
		throw;
	      }
	    if (size >= 0)
	      {
		buf.set_size(size);
		http_in(buf);
	      }
	    else if (size == SSLConst::SHOULD_RETRY)
	      break;
	    else if (size == SSLConst::PEER_CLOSE_NOTIFY)
	      parent().base_error_handler(STATUS::E_EOF_SSL, "SSL PEER_CLOSE_NOTIFY");
	    else
	      throw http_exception("unknown read status from SSL layer");
	  }
      }

      size_t http_buf_size() const
      {
	return (*frame)[Frame::WRITE_HTTP].payload();
      }

      static CONTENT_LENGTH_TYPE get_content_length(const HTTP::HeaderList& headers)
      {
	const std::string transfer_encoding = headers.get_value_trim("transfer-encoding");
	if (!string::strcasecmp(transfer_encoding, "chunked"))
	  {
	    return CONTENT_INFO::CHUNKED;
	  }
	else
	  {
	    const std::string content_length_str = headers.get_value_trim("content-length");
	    if (content_length_str.empty())
	      return 0;
	    const CONTENT_LENGTH_TYPE content_length = parse_number_throw<CONTENT_LENGTH_TYPE>(content_length_str, "content-length");
	    if (content_length < 0)
	      throw number_parse_exception("content-length is < 0");
	    return content_length;
	  }
      }

      // private member vars

      typename REQUEST_REPLY::Parser::status rr_status;
      typename REQUEST_REPLY::Parser rr_parser;
      typename REQUEST_REPLY::State rr_obj;

      unsigned int rr_header_bytes;

      CONTENT_LENGTH_TYPE rr_content_bytes;
      CONTENT_LENGTH_TYPE rr_content_length;  // Content-Length in header
      std::unique_ptr<ChunkedHelper> rr_chunked;

      enum HTTPOutState {
	S_PRE,
	S_OUT,
	S_EOF,
	S_DONE
      };
      HTTPOutState out_state;
    };

  }
}

#endif
