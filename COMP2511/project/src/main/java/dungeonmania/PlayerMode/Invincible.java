package dungeonmania.PlayerMode;

public class Invincible implements PlayerMode {
    private int duration;
    private final String providerId;
    private final String providerType;

    public Invincible(int duration, String providerId, String providerType) {
        this.duration = duration;
        this.providerId = providerId;
        this.providerType = providerType;
    }

    @Override
    public String providerId() {
        return providerId;
    }

    @Override
    public String providerType() {
        return providerType;
    }
    @Override
    public void oneTick() {
        duration--;
    }
    @Override
    public int getDuration() {
        return duration;
    }
}
