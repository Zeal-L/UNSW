package unsw.crown;

/**
 * @author Braedon Wooding, and @your name
 */
public enum CheckerColor {
    WHITE("white", "purple"),
    RED("red", "silver");

    private String color;
    private String specialColor;

    private CheckerColor(String color, String specialColor) {
        this.color = color;
        this.specialColor = specialColor;
    }

    public String getColor() {
        return color;
    }

    public CheckerColor toggleColor() {
        switch (this) {
            case RED: return CheckerColor.WHITE;
            case WHITE: return CheckerColor.RED;
        }
        return null;
    }

    public String getSpecialColor() {
        return specialColor;
    }
}