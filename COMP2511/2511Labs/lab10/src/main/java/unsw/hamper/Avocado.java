package unsw.hamper;

public class Avocado extends Fruit {
    private int unitPrice;

    public Avocado(String name, int unitPrice) {
        super(name);
        this.unitPrice = unitPrice;
    }

    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) return false;
        Avocado other = (Avocado) obj;
        if (unitPrice != other.unitPrice) return false;
        return true;
    }

    public int getPrice(){
        return unitPrice;
    }

    @Override
    public String toString(){
        return super.toString()+" unitPrice="+unitPrice;
    }
}
