package unsw.shipping;

public class Decorator extends Product {

    private Product product;

    public Decorator(Product product) {
        this.product = product;
    }

    @Override
    public double getPrice() {
        return product.getPrice();
    }

    @Override
    public int getWeight() {
        return product.getWeight();
    }

    @Override
    public double getShippingCost() {
        return product.getShippingCost();
    }

}