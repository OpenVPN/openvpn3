// API for OpenVPN Client, intended to be wrapped by swig.
// Use ovpncli.i to wrap the API.
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
    struct ServerEntry {
      std::string server;
      std::string friendlyName;
    };

    // return properties of config
    struct EvalConfig
    {
      EvalConfig() : error(false), staticChallengeEcho(false) {}

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

    // used to pass credentials to VPN client
    struct ProvideCreds
    {
      ProvideCreds() : replacePasswordWithSessionID(false) {}

      std::string username;
      std::string password;

      // response to challenge
      std::string response;

      // Dynamic challenge/reponse cookie
      std::string dynamicChallengeCookie;

      // If true, on successful connect, we will replace the password
      // with the session ID we receive from the server.
      bool replacePasswordWithSessionID;
    };

    // used to pass credentials to VPN client
    struct DynamicChallenge
    {
      DynamicChallenge() : echo(false), responseRequired(false) {}

      std::string challenge;
      bool echo;
      bool responseRequired;
    };

    // OpenVPN config-file/profile
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
    };

    // used to communicate VPN events such as connect, disconnect, etc.
    struct Event
    {
      Event() : error(false) {}
      bool error;            // true if error
      std::string name;      // event name
      std::string info;      // additional event info
    };

    // returned by some methods as a status/error indication
    struct Status
    {
      Status() : error(false) {}
      bool error;           // true if error
      std::string message;  // if error, message given here
    };

    // used to pass log lines
    struct LogInfo
    {
      LogInfo(const std::string& str) : text(str) {}
      std::string text;     // log output (usually but not always one line)
    };

    // base class for External PKI queries
    struct ExternalPKIRequestBase {
      ExternalPKIRequestBase() : error(false), invalidAlias(false) {}

      bool error;              // true if error occurred
      std::string errorText;  // text describing error
      bool invalidAlias;      // true if the error is caused by an invalid alias
      std::string alias;       // the alias string, used to query cert/key
    };

    // used to query for External PKI certificate
    struct ExternalPKICertRequest : public ExternalPKIRequestBase
    {
      std::string cert;
    };

    // used to request an RSA signature
    struct ExternalPKISignRequest : public ExternalPKIRequestBase
    {
      std::string data;  // data rendered as base64
      std::string sig;   // RSA signature, rendered as base64
    };

    namespace Private {
      struct ClientState;
    };

    // Top-level OpenVPN client class that is wrapped by swig.
    class OpenVPNClient : public TunBuilderBase, private ExternalPKIBase {
    public:
      OpenVPNClient();
      virtual ~OpenVPNClient();

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
