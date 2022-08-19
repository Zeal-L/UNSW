package unsw.hamper;

public class PlasticToyCar extends ToyCar {
    private int price;

    public PlasticToyCar(int price){
        this.price = price;
    }

    @Override
    public int getPrice() {
        return price;
    }

    @Override
    public String toString(){
        return super.toString()+" price="+price;
    }
}
