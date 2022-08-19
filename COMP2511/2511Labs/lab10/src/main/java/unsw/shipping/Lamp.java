package unsw.shipping;

public class Lamp extends Product {

    @Override
    public double getPrice() {
        return 50;
    }

    @Override
    public int getWeight() {
        return 900;
    }

}
