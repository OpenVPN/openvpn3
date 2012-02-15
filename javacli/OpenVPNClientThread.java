public class OpenVPNClientThread extends OpenVPNClientBase implements Runnable {
    private EventReceiver parent;
    private Status connect_status;

    public interface EventReceiver {
	void event(Event event);
	void log(LogInfo loginfo);
    }

    public OpenVPNClientThread() {
	parent = null;
    }

    public Status connect(EventReceiver parent_arg) {
	// direct client callbacks to parent
	parent = parent_arg;

	// execute client in a worker thread
	Thread thread = new Thread(this);
	thread.start();

	// wait for worker thread to complete
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

	return connect_status;
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
	connect_status = super.connect();
    }
}
