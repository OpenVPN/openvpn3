import java.io.*;
import java.nio.charset.Charset;

public class Client extends OpenVPNClient implements Runnable {
    private ProvideCreds creds_;

    // utility method to read a text file
    public static String readTextFile(String file, String csName)
	throws IOException {
	Charset cs = Charset.forName(csName);
	return readTextFile(file, cs);
    }

    public static String readTextFile(String file, Charset cs)
	throws IOException {
	// No real need to close the BufferedReader/InputStreamReader
	// as they're only wrapping the stream
	FileInputStream stream = new FileInputStream(file);
	try {
	    Reader reader = new BufferedReader(new InputStreamReader(stream, cs));
	    StringBuilder builder = new StringBuilder();
	    char[] buffer = new char[8192];
	    int read;
	    while ((read = reader.read(buffer, 0, buffer.length)) > 0) {
		builder.append(buffer, 0, read);
	    }
	    return builder.toString();
	} finally {
	    // Potential issue here: if this throws an IOException,
	    // it will mask any others. Normally I'd use a utility
	    // method which would log exceptions and swallow them
	    stream.close();
	}
    }

    // Load OpenVPN core (implements OpenVPNClient) from shared library 
    static {
	System.loadLibrary("ovpncli");
    }

    public static void main(String[] args) throws InterruptedException, IOException {
	if (args.length >= 1)
	    {
		// load config file
		Config config = new Config();
		config.setContent(readTextFile(args[0], "UTF-8"));

		// parse config file
		final Client client = new Client();
		Status s = client.parse_config(config);
		if (s.getError())
		    {
			System.err.println("OpenVPN config file parse error: " + s.getMessage());
			System.exit(1);
		    }

		// handle creds
		ProvideCreds creds = new ProvideCreds();
		RequestCreds need = client.needed_creds();
		String auth_type = need.getAuthType();
		if (auth_type.equals("auth"))
		    {
			if (args.length >= 3)
			    {
				creds.setUsername(args[1]);
				creds.setPassword(args[2]);
			    }
			else
			    {
				System.err.println("OpenVPN config file requires username/password but none provided");
				System.exit(1);
			    }
		    }
		client.provide_creds(creds);

		// catch signals
		final Thread mainThread = Thread.currentThread();
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
			    client.stop();
			    try {
				mainThread.join();
			    } catch (InterruptedException e) {
			    }

			}
		    });

		// execute client in a worker thread
		Thread thread = new Thread(client);
		thread.start();

		// wait for work thread to complete
		thread.join();
	    }
	else
	    {
		System.err.println("OpenVPN Java client");
		System.err.println("Usage: java Client <client.ovpn> [username] [password]");
		System.exit(2);
	    }
    }

    Client() {
    }

    public void provide_creds(ProvideCreds creds)
    {
	creds_ = creds;
    }

    public void run() {
	Status status = super.connect(creds_);
	System.out.format("END Status: err=%b msg='%s'%n", status.getError(), status.getMessage());
    }

    @Override
    public void event(Event event) {
	boolean error = event.getError();
	String name = event.getName();
	String info = event.getInfo();
	System.out.format("EVENT: err=%b name=%s info='%s'%n", error, name, info);
    }

    @Override
    public void log(LogInfo loginfo) {
	String text = loginfo.getText();
	System.out.format("LOG: %s", text);
    }
 }
