public class Client implements OpenVPNClientThread.EventReceiver {
    private OpenVPNClientThread client_impl;

    public static class ConfigError extends Exception {
	public ConfigError(String msg) { super(msg); }
    }

    public static class CredsUnspecifiedError extends Exception {
	public CredsUnspecifiedError(String msg) { super(msg); }
    }

    // Load OpenVPN core (implements OpenVPNClientBase) from shared library 
    static {
	System.loadLibrary("ovpncli");
    }

    public Client(String config_text, String username, String password) throws ConfigError, CredsUnspecifiedError {
	// init client implementation object
	client_impl = new OpenVPNClientThread();

	// load/eval config
	Config config = new Config();
	config.setContent(config_text);
	EvalConfig ec = client_impl.eval_config(config);
	if (ec.getError())
	    throw new ConfigError("OpenVPN config file parse error: " + ec.getMessage());

	// handle creds
	ProvideCreds creds = new ProvideCreds();
	if (!ec.getAutologin())
	    {
		if (username.length() > 0)
		    {
			creds.setUsername(username);
			creds.setPassword(password);
		    }
		else
		    throw new CredsUnspecifiedError("OpenVPN config file requires username/password but none provided");
	    }
	client_impl.provide_creds(creds);
    }

    public void connect() {
	// connect
	Status status = client_impl.connect(this);

	// show connect status
	System.out.format("END Status: err=%b msg='%s'%n", status.getError(), status.getMessage());
    }

    public void stop() {
	client_impl.stop();
    }

    public void show_stats() {
	int n = client_impl.stats_n();
	for (int i = 0; i < n; ++i)
	    {
		String name = client_impl.stats_name(i);
		long value = client_impl.stats_value(i);
		if (value > 0)
		    System.out.format("STAT %s=%s%n", name, value);
	    }
    }

    public void event(Event event) {
	boolean error = event.getError();
	String name = event.getName();
	String info = event.getInfo();
	System.out.format("EVENT: err=%b name=%s info='%s'%n", error, name, info);
    }

    public void log(LogInfo loginfo) {
	String text = loginfo.getText();
	System.out.format("LOG: %s", text);
    }
 }
