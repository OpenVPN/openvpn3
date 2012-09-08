//
//  ovpncli.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// API for OpenVPN Client, may be used standalone or wrapped by swig.
// Use ovpncli.i to wrap the API for swig.
// The crux of the API is defined in OpenVPNClient (below)
// and TunBuilderBase.

#include <string>
#include <vector>

#include <openvpn/tun/builder/base.hpp>
#include <openvpn/pki/epkibase.hpp>

namespace openvpn {
  class OptionList;

  namespace ClientAPI {
    // Represents an OpenVPN server and its friendly name
    // (client reads)
    struct ServerEntry {
      std::string server;
      std::string friendlyName;
    };

    // return properties of config
    // (client reads)
    struct EvalConfig
    {
      EvalConfig() : error(false), autologin(false), externalPki(false), staticChallengeEcho(false) {}

      // true if error
      bool error;

      // if error, message given here
      std::string message;

      // this username must be used with profile
      std::string userlockedUsername;

      // profile name of config
      std::string profileName;

      // "friendly" name of config
      std::string friendlyName;

      // true: no creds required, false: username/password required
      bool autologin;

      // if true, this is an External PKI profile (no cert or key directives)
      bool externalPki;

      // static challenge, may be empty, ignored if autologin
      std::string staticChallenge;

      // true if static challenge response should be echoed to UI, ignored if autologin
      bool staticChallengeEcho;

      // optional list of user-selectable VPN servers
      std::vector<ServerEntry> serverList;
    };

    // used to pass credentials to VPN core
    // (client writes)
    struct ProvideCreds
    {
      ProvideCreds() : replacePasswordWithSessionID(false) {}

      std::string username;
      std::string password;

      // response to challenge
      std::string response;

      // Dynamic challenge/response cookie
      std::string dynamicChallengeCookie;

      // If true, on successful connect, we will replace the password
      // with the session ID we receive from the server.
      bool replacePasswordWithSessionID;
    };

    // used to get session token from VPN core
    // (client reads)
    struct SessionToken
    {
      std::string username;
      std::string session_id; // an OpenVPN Session ID, used as a proxy for password
    };

    // used to query challenge/response from user
    // (client reads)
    struct DynamicChallenge
    {
      DynamicChallenge() : echo(false), responseRequired(false) {}

      std::string challenge;
      bool echo;
      bool responseRequired;
    };

    // OpenVPN config-file/profile
    // (client writes)
    struct Config
    {
      Config() : connTimeout(0) {}

      // OpenVPN config file (profile) as a string
      std::string content;

      // User wants to use a different server than that specified in "remote"
      // option of config file
      std::string serverOverride;

      // User wants to force a given transport protocol
      std::string protoOverride;

      // Connection timeout in seconds, or 0 to retry indefinitely
      int connTimeout;

      // An ID used for get-certificate and RSA signing callbacks
      // for External PKI profiles.
      std::string externalPkiAlias;

      // Compression mode, one of:
      // yes -- support compression on both uplink and downlink
      // asym -- support compression on downlink only (i.e. server -> client)
      // no (default if empty) -- support compression stubs only
      std::string compressionMode;
    };

    // used to communicate VPN events such as connect, disconnect, etc.
    // (client reads)
    struct Event
    {
      Event() : error(false) {}
      bool error;            // true if error
      std::string name;      // event name
      std::string info;      // additional event info
    };

    // used to communicate extra details about successful connection
    // (client reads)
    struct ConnectionInfo
    {
      ConnectionInfo() : defined(false) {}

      bool defined;
      std::string user;
      std::string serverHost;
      std::string serverPort;
      std::string serverProto;
      std::string serverIp;
      std::string vpnIp;
      std::string tunName;
    };

    // returned by some methods as a status/error indication
    // (client reads)
    struct Status
    {
      Status() : error(false) {}
      bool error;           // true if error
      std::string message;  // if error, message given here
    };

    // used to pass log lines
    // (client reads)
    struct LogInfo
    {
      LogInfo(const std::string& str) : text(str) {}
      std::string text;     // log output (usually but not always one line)
    };

    // used to pass stats for an interface
    struct InterfaceStats
    {
      long long bytesIn;
      long long packetsIn;
      long long errorsIn;
      long long bytesOut;
      long long packetsOut;
      long long errorsOut;
    };

    // used to pass basic transport stats
    struct TransportStats
    {
      long long bytesIn;
      long long bytesOut;
      long long packetsIn;
      long long packetsOut;

      // number of binary milliseconds (1/1024th of a second) since
      // last packet was received, or -1 if undefined
      int lastPacketReceived;
    };

    // base class for External PKI queries
    struct ExternalPKIRequestBase {
      ExternalPKIRequestBase() : error(false), invalidAlias(false) {}

      bool error;             // true if error occurred (client writes)
      std::string errorText;  // text describing error (client writes)
      bool invalidAlias;      // true if the error is caused by an invalid alias (client writes)
      std::string alias;      // the alias string, used to query cert/key (client reads)
    };

    // used to query for External PKI certificate
    struct ExternalPKICertRequest : public ExternalPKIRequestBase
    {
      std::string cert; // (client writes)
    };

    // used to request an RSA signature
    struct ExternalPKISignRequest : public ExternalPKIRequestBase
    {
      std::string data;  // data rendered as base64 (client reads)
      std::string sig;   // RSA signature, rendered as base64 (client writes)
    };

    namespace Private {
      struct ClientState;
    };

    // Top-level OpenVPN client class.
    class OpenVPNClient : public TunBuilderBase, private ExternalPKIBase {
    public:
      OpenVPNClient();
      virtual ~OpenVPNClient();

      // Call me first, before calling any other method (static or instance methods)
      // in this class.
      static void init_process();

      // Parse config file and determine needed credentials statically.
      static EvalConfig eval_config_static(const Config&);

      // Parse a dynamic challenge cookie, placing the result in dc.
      // Return true on success or false if parse error.
      static bool parse_dynamic_challenge(const std::string& cookie, DynamicChallenge& dc);

      // Parse OpenVPN configuration file.
      EvalConfig eval_config(const Config&);

      // Provide credentials and other options.  Call before connect().
      Status provide_creds(const ProvideCreds&);

      // Callback to "protect" a socket from being routed through the tunnel.
      // Will be called from the thread executing connect().
      virtual bool socket_protect(int socket) = 0;

      // Primary VPN client connect method, doesn't return until disconnect.
      // Should be called by a worker thread.  This method will make callbacks
      // to event() and log() functions.  Make sure to call eval_config()
      // and possibly provide_creds() as well before this function.
      Status connect();

      // Return information about the most recent connection.  Should be called
      // after an event of type "CONNECTED".
      ConnectionInfo connection_info();

      // Writes current session token to tok and returns true.
      // If session token is unavailable, false is returned and
      // tok is unmodified.
      bool session_token(SessionToken& tok);

      // Stop the client.  Only meaningful when connect() is running.
      // May be called asynchronously from a different thread
      // when connect() is running.
      void stop();

      // Pause the client -- useful to avoid continuous reconnection attempts
      // when network is down.  May be called from a different thread
      // when connect() is running.
      void pause();

      // Resume the client after it has been paused.  May be called from a
      // different thread when connect() is running.
      void resume();

      // Do a disconnect/reconnect cycle n seconds from now.  May be called
      // from a different thread when connect() is running.
      void reconnect(int seconds);

      // Get stats/error info.  May be called from a different thread
      // when connect() is running.

      // number of stats
      static int stats_n();

      // return a stats name, index should be >= 0 and < stats_n()
      static std::string stats_name(int index);

      // return a stats value, index should be >= 0 and < stats_n()
      long long stats_value(int index) const;

      // return all stats in a bundle
      std::vector<long long> stats_bundle() const;

      // return tun stats only
      InterfaceStats tun_stats() const;

      // return transport stats only
      TransportStats transport_stats() const;

      // Callback for delivering events during connect() call.
      // Will be called from the thread executing connect().
      virtual void event(const Event&) = 0;

      // Callback for logging.
      // Will be called from the thread executing connect().
      virtual void log(const LogInfo&) = 0;

      // External PKI callbacks
      // Will be called from the thread executing connect().
      virtual void external_pki_cert_request(ExternalPKICertRequest&) = 0;
      virtual void external_pki_sign_request(ExternalPKISignRequest&) = 0;

      // Returns date/time of app expiration as a unix time value
      static int app_expire();

      // Returns core copyright
      static std::string copyright();

    private:
      static void parse_config(const Config&, EvalConfig&, OptionList&);
      void parse_extras(const Config&, EvalConfig&);
      void external_pki_error(const ExternalPKIRequestBase&, const size_t err_type);
      void check_app_expired();

      // from ExternalPKIBase
      virtual bool sign(const std::string& data, std::string& sig);

      // disable copy and assignment
      OpenVPNClient(const OpenVPNClient&);
      OpenVPNClient& operator=(const OpenVPNClient&);

      Private::ClientState* state;
    };

  }
}
