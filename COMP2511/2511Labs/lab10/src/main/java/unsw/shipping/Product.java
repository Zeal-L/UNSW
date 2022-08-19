package unsw.shipping;

public abstract class Product {

    public abstract double getPrice();

    public abstract int getWeight();

    public double getShippingCost() {
        //Shipping is $2 per kg rounded up to the nearest kg.
        return (getWeight()/1000 + 1)*2;
    }

}
