// package OPENVPN_PACKAGE

public class OpenVPNClientThread extends OpenVPNClientBase implements Runnable {
    private EventReceiver parent;
    private TunBuilder tun_builder;
    private Thread thread;
    private Status connect_status_;

    public interface EventReceiver {
	// Called with events from core
	void event(Event event);

	// Called with log text from core
	void log(LogInfo loginfo);

	// Called when connect() thread exits
	void done(Status status);

	// Called to "protect" a socket from being routed through the tunnel
	boolean socket_protect(int socket);

	// Callback to construct a new tun builder
	TunBuilder tun_builder_new();
    }

    public interface TunBuilder {
	// Tun builder methods.  All methods returning boolean use the return
	// value to indicate success (true) or fail (false).

	// Callback to to add network address to VPN interface
	boolean tun_builder_add_address(String address, int prefix_length);

	// Callback to add route to VPN interface
	boolean tun_builder_add_route(String address, int prefix_length);

	// Callback to add DNS server to VPN interface
	boolean tun_builder_add_dns_server(String address);

	// Callback to add search domain to DNS resolver
	boolean tun_builder_add_search_domain(String domain);

	// Callback to set MTU of the VPN interface
	boolean tun_builder_set_mtu(int mtu);

	// Callback to set the session name
	boolean tun_builder_set_session_name(String name);

	// Callback to establish the VPN tunnel, returning a file descriptor
	// to the tunnel, which the caller will henceforth own.  Returns -1
	// if the tunnel could not be established.
	int tun_builder_establish();
    }

    public OpenVPNClientThread() {
	parent = null;
	tun_builder = null;
	thread = null;
	connect_status_ = null;
    }

    // start connect session in worker thread
    public void connect(EventReceiver parent_arg) {
	// direct client callbacks to parent
	parent = parent_arg;

	// clear status
	connect_status_ = null;

	// execute client in a worker thread
	thread = new Thread(this, "OpenVPNClientThread");
	thread.start();
    }

    // wait for worker thread to complete; to stop thread,
    // first call super stop() method then wait_thread()
    public void wait_thread() {
	if (thread != null) {
	    boolean interrupted;
	    do {
		interrupted = false;
		try {
		    thread.join();
		}
		catch (InterruptedException e) {
		    interrupted = true;
		    super.stop(); // send thread a stop message
		}
	    } while (interrupted);

	    // dissassociate client callbacks from parent
	    parent = null;
	    thread = null;
	}
    }

    public Status connect_status() {
	return connect_status_;
    }

    // Runnable overrides

    @Override
    public void run() {
	connect_status_ = super.connect();
	if (parent != null)
	    parent.done(connect_status_);
    }

    // OpenVPNClientBase (C++ class) overrides

    @Override
    public boolean socket_protect(int socket) {
	if (parent != null)
	    return parent.socket_protect(socket);
	else
	    return false;
    }

    @Override
    public void event(Event event) {
	if (parent != null)
	    parent.event(event);
    }

    @Override
    public void log(LogInfo loginfo) {
	if (parent != null)
	    parent.log(loginfo);
    }

    // TunBuilderBase (C++ class) overrides

    @Override
    public boolean tun_builder_new() {
	if (parent != null) {
	    tun_builder = parent.tun_builder_new();
	    return tun_builder != null;
	} else
	    return false;
    }

    @Override
    public boolean tun_builder_add_address(String address, int prefix_length) {
	if (tun_builder != null)
	    return tun_builder.tun_builder_add_address(address, prefix_length);
	else
	    return false;
    }

    @Override
    public boolean tun_builder_add_route(String address, int prefix_length) {
	if (tun_builder != null)
	    return tun_builder.tun_builder_add_route(address, prefix_length);
	else
	    return false;
    }

    @Override
    public boolean tun_builder_add_dns_server(String address) {
	if (tun_builder != null)
	    return tun_builder.tun_builder_add_dns_server(address);
	else
	    return false;
    }

    @Override
    public boolean tun_builder_add_search_domain(String domain)
    {
	if (tun_builder != null)
	    return tun_builder.tun_builder_add_search_domain(domain);
	else
	    return false;
    }

    @Override
    public boolean tun_builder_set_mtu(int mtu) {
	if (tun_builder != null)
	    return tun_builder.tun_builder_set_mtu(mtu);
	else
	    return false;
    }

    @Override
    public boolean tun_builder_set_session_name(String name)
    {
	if (tun_builder != null)
	    return tun_builder.tun_builder_set_session_name(name);
	else
	    return false;
    }

    @Override
    public int tun_builder_establish() {
	if (tun_builder != null)
	    return tun_builder.tun_builder_establish();
	else
	    return -1;
    }
}
