// Java-callable API for OpenVPN Client.
// Use ovpncli.i to wrap the API for Java.
// The crux of the API is defined in OpenVPNClientBase (below)
// and TunBuilderBase.  OpenVPNClientThread.java is used
// to wrap the API on the Java side.

#include <string>

#include <openvpn/tun/builder/base.hpp>

namespace openvpn {
  class OptionList;

  namespace ClientAPI {
    // return properties of config
    struct EvalConfig
    {
      EvalConfig() : error(false), staticChallengeEcho(false) {}

      // true if error
      bool error;

      // if error, message given here
      std::string message;

      // true: no creds required, false: username/password required
      bool autologin;

      // static challenge, may be empty, ignored if autologin
      std::string staticChallenge;

      // true if static challenge response should be echoed to UI, ignored if autologin
      bool staticChallengeEcho;
    };

    // used to pass credentials to VPN client
    struct ProvideCreds
    {
      ProvideCreds() : replacePasswordWithSessionID(false) {}

      std::string username;
      std::string password;

      // response to static challenge
      std::string staticResponse;

      // If true, on successful connect, we will replace the password
      // with the session ID we receive from the server.
      bool replacePasswordWithSessionID;
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
      std::string text;     // log output (usually but not always one line)
    };

    namespace Private {
      struct ClientState;
    };

    // Top-level OpenVPN client class that is wrapped by swig.
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

      // Callback for delivering events during connect() call.
      // Will be called from the thread executing connect().
      virtual void event(const Event&) = 0;

      // Callback for logging.
      // Will be called from the thread executing connect().
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
