public interface ClientEventReceiver {
    void event(Event event);
    void log(LogInfo loginfo);
}
