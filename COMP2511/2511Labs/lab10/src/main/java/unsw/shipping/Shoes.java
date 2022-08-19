package unsw.shipping;

public class Shoes extends Product {

    @Override
    public double getPrice() {
        return 90;
    }

    @Override
    public int getWeight() {
        return 100;
    }

}
