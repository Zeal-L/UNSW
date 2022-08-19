package dungeonmania.PlayerMode;

public interface PlayerMode {
    String providerId();
    String providerType();
    void oneTick();
    int getDuration();
}
