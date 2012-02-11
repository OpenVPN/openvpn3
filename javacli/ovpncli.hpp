namespace openvpn {
  namespace ClientAPI {

    struct RequestCreds
    {
      // used by VPN client to indicate which credentials are required
      RequestCreds() : staticChallengeEcho(false) {}
      std::string authType;              // "autologin" (no creds required) or "auth" (username/password required)
      std::string staticChallenge;       // static challenge, may be empty
      bool staticChallengeEcho;          // true if static challenge response should be echoed to UI
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

    // used to pass operational statistics such as bandwidth usage
    struct Stats
    {
      Stats() : bytesIn(0), bytesOut(0) {}
      long long bytesIn;
      long long bytesOut;
    };

    namespace Private {
      struct ClientState;
    };

    // Top-level OpenVPN client class that is wrapped by swig
    class OpenVPNClient {
    public:
      OpenVPNClient();
      virtual ~OpenVPNClient();

      // Parse OpenVPN configuration file.
      Status parse_config(const Config&);

      // Determine needed credentials, call after parse_config()
      // but before connect().
      RequestCreds needed_creds();

      // Primary VPN client connect method, doesn't return until disconnect.
      // Should be called by a worker thread.  This method will make callbacks
      // to event() and log() functions.  Make sure to call parse_config()
      // before this function.
      Status connect(const ProvideCreds&);

      // Stop the client.  Only meaningful when connect() is running.
      // Intended to be called asynchronously from a different thread
      // when connect() is running.
      void stop();

      // Return usage stats.
      Stats stats() const;

      // Callback for delivering events during connect() call.
      virtual void event(const Event&) = 0;

      // Callback for logging.
      virtual void log(const LogInfo&) = 0;

    private:
      // disable copy and assignment
      OpenVPNClient(const OpenVPNClient&);
      OpenVPNClient& operator=(const OpenVPNClient&);

      Private::ClientState* state;
    };

  }
}
