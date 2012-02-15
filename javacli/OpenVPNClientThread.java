public class OpenVPNClientThread extends OpenVPNClientBase implements Runnable {
    private EventReceiver parent;
    private Thread thread;
    private Status connect_status_;

    public interface EventReceiver {
	void event(Event event);
	void log(LogInfo loginfo);
    }

    public OpenVPNClientThread() {
	parent = null;
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

    @Override
    public void run() {
	connect_status_ = super.connect();
    }
}
