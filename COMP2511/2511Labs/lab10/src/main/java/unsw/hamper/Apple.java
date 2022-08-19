package unsw.hamper;

public class Apple extends Fruit {
    private int pricePerKilo;
    private int weightKilos;

    public Apple(String name, int pricePerKilo, int weightKilos) {
        super(name);
        this.pricePerKilo = pricePerKilo;
        this.weightKilos = weightKilos;
    }

    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) return false;
        Apple other = (Apple) obj;
        if (pricePerKilo != other.pricePerKilo || weightKilos != other.weightKilos) return false;
        return true;
    }

    public int getPrice(){
        return pricePerKilo*weightKilos;
    }

    @Override
    public String toString(){
        return super.toString()+" pricePerKilo="+pricePerKilo+" weightKilos="+weightKilos;
    }
}
