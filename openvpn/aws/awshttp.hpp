//
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc. All rights reserved.
//

// Build HTTPS context for AWS queries

#ifndef OPENVPN_AWS_AWSHTTP_H
#define OPENVPN_AWS_AWSHTTP_H

#include <string>
#include <utility>

#include <openvpn/frame/frame_init.hpp>
#include <openvpn/crypto/digestapi.hpp>
#include <openvpn/ws/httpcliset.hpp>
#include <openvpn/aws/awsca.hpp>
#include <openvpn/ssl/sslchoose.hpp>

namespace openvpn {
  namespace AWS {
    class HTTPContext
    {
    public:
      HTTPContext(RandomAPI::Ptr rng,
		  const int debug_level)
	: frame_(frame_init_simple(2048)),
	  digest_factory_(new CryptoDigestFactory<SSLLib::CryptoAPI>()),
	  rng_(std::move(rng)),
	  debug_level_(debug_level)
      {
      }

      WS::ClientSet::TransactionSet::Ptr transaction_set(std::string host) const
      {
	WS::ClientSet::TransactionSet::Ptr ts = new WS::ClientSet::TransactionSet;
	ts->host.host = std::move(host);
	ts->host.port = "443";
	ts->http_config = http_config();
	ts->max_retries = 10;
	ts->retry_duration = Time::Duration::seconds(1);
	ts->debug_level = debug_level_;
	return ts;
      }

      int debug_level() const
      {
	return debug_level_;
      }

      DigestFactory& digest_factory() const
      {
	return *digest_factory_;
      }

      RandomAPI* rng() const
      {
	return rng_.get();
      }

    private:
      WS::Client::Config::Ptr http_config() const
      {
	// SSL flags
	unsigned int ssl_flags = 0;
	if (debug_level_ >= 2)
	  ssl_flags |= SSLConst::LOG_VERIFY_STATUS;

	// make SSL context using awspc_web_cert() as our CA bundle
	SSLLib::SSLAPI::Config::Ptr ssl(new SSLLib::SSLAPI::Config);
	ssl->set_mode(Mode(Mode::CLIENT));
	ssl->load_ca(api_ca(), false);
	ssl->set_local_cert_enabled(false);
	ssl->set_tls_version_min(TLSVersion::V1_2);
	ssl->set_remote_cert_tls(KUParse::TLS_WEB_SERVER);
	ssl->set_flags(ssl_flags);
	ssl->set_frame(frame_);
	ssl->set_rng(rng_);

	// make HTTP context
	WS::Client::Config::Ptr hc(new WS::Client::Config());
	hc->frame = frame_;
	hc->ssl_factory = ssl->new_factory();
	hc->user_agent = "OpenVPN-PG";
	hc->connect_timeout = 30;
	hc->general_timeout = 60;
	return hc;
      }

      Frame::Ptr frame_;
      DigestFactory::Ptr digest_factory_;
      RandomAPI::Ptr rng_;
      int debug_level_;
    };
  }
}

#endif
