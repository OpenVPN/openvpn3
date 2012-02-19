#include <string>

#include <openvpn/tun/builder/base.hpp>

namespace openvpn {
  class OptionList;

  namespace ClientAPI {
    // return properties of config
    struct EvalConfig
    {
      EvalConfig() : error(false), staticChallengeEcho(false) {}

      bool error;                        // true if error
      std::string message;               // if error, message given here

      bool autologin;                    // true: no creds required, false: username/password required
      std::string staticChallenge;       // static challenge, may be empty, ignored if autologin
      bool staticChallengeEcho;          // true if static challenge response should be echoed to UI, ignored if autologin
    };

    // used to pass credentials to VPN client
    struct ProvideCreds
    {
      std::string username;
      std::string password;
      std::string staticResponse; // response to static challenge
    };

    // OpenVPN config-file/profile
    struct Config
    {
      std::string content;
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
      std::string text;                         // log output (usually but not always one line)
    };

    namespace Private {
      struct ClientState;
    };

    // Top-level OpenVPN client class that is wrapped by swig
    class OpenVPNClientBase : public TunBuilderBase {
    public:
      OpenVPNClientBase();
      virtual ~OpenVPNClientBase();

      // Parse config file and determine needed credentials statically.
      static EvalConfig eval_config_static(const Config&);

      // Parse OpenVPN configuration file.
      EvalConfig eval_config(const Config&) const;

      // Provide credentials.  Call before connect() if needed_creds()
      // indicates that credentials are needed.
      void provide_creds(const ProvideCreds&);

      // Callback to "protect" a socket from being routed through the tunnel
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

      // Get stats/error info
      static int stats_n();                      // number of stats
      static std::string stats_name(int index);  // return a stats name, index should be >= 0 and < stats_n()
      long long stats_value(int index) const;    // return a stats value, index should be >= 0 and < stats_n()

      // Callback for delivering events during connect() call.
      virtual void event(const Event&) = 0;

      // Callback for logging.
      virtual void log(const LogInfo&) = 0;

    private:
      static void parse_config(const Config& config, EvalConfig& eval, OptionList& options);

      // disable copy and assignment
      OpenVPNClientBase(const OpenVPNClientBase&);
      OpenVPNClientBase& operator=(const OpenVPNClientBase&);

      Private::ClientState* state;
    };

  }
}
