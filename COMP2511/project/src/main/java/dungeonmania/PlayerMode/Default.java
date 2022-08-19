package dungeonmania.PlayerMode;

public class Default implements PlayerMode {

    public Default() {
    }

    @Override
    public String providerId() {
        return null;
    }

    @Override
    public String providerType() {
        return null;
    }
    @Override
    public void oneTick() {}
    @Override
    public int getDuration() {
        return 1;
    }
}
