package unsw.hamper;

public class PremiumToyCar extends ToyCar {
    private int price;

    public PremiumToyCar(int price){
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
