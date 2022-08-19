package unsw.hamper;

public abstract class Item {
    public abstract int getPrice();

    @Override
    public String toString(){
        return getClass().getName();
    }
}
