// TESTING_ONLY

import java.io.*;
import java.nio.charset.Charset;

public class Main {
    // utility method to read a text file
    public static String readTextFile(String file, String csName) throws IOException {
	Charset cs = Charset.forName(csName);
	return readTextFile(file, cs);
    }

    public static String readTextFile(String file, Charset cs) throws IOException {
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

    public static void main(String[] args) throws IOException, Client.ConfigError, Client.CredsUnspecifiedError {
	if (args.length >= 1)
	    {
		// load config file
		String config = readTextFile(args[0], "UTF-8");

		// get creds
		String username = "";
		String password = "";
		if (args.length >= 3)
		    {
			username = args[1];
			password = args[2];
		    }

		// instantiate client object
		final Client client = new Client(config, username, password);

		// catch signals
		final Thread mainThread = Thread.currentThread();
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
			    client.stop();
			    try {
				mainThread.join();
			    }
			    catch (InterruptedException e) {
			    }
			}
		    });

		// execute client session
		client.connect();

		// show stats before exit
		client.show_stats();
	    }
	else
	    {
		System.err.println("OpenVPN Java client");
		System.err.println("Usage: java Client <client.ovpn> [username] [password]");
		System.exit(2);
	    }
    }
}
