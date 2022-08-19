package unsw.hamper;

public class CreativeHamper extends ArrayListItemHamper<Item> {
    /**
     * invariant: if hamper contains 5 or more items, it must contain at least 2 toy cars (at least 1 must be premium) and at least 2 fruits. Otherwise, adding an item should do nothing
     * creative hamper has a price surcharge of $10
     */


    @Override
    public int getPrice(){
        // TODO implement this
        return 0;
    }

    @Override
    public void add(Item e, int n){
        // TODO implement this
    }
}
