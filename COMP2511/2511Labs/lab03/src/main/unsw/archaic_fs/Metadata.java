package unsw.archaic_fs;

public class Metadata {
    private DeviceType type;

    public Metadata(DeviceType type) {
        this.type = type;
    }

    public DeviceType getType() {
        return type;
    }
}
