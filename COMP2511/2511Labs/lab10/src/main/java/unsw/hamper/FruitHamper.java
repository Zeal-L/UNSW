package unsw.hamper;

public class FruitHamper extends ArrayListItemHamper<Fruit> {
    /**
     * invariant: FruitHamper must have at least 2 apples and 2 avocados when have >= 6 fruits. Otherwise, adding an item should do nothing
     * fruit hamper has price surcharge of 25%, rounded up to nearest integer
     */

    @Override
    public int getPrice(){
        // TODO implement this
        return 0;
    }

    @Override
    public void add(Fruit e, int n){
        // TODO implement this
    }
}
