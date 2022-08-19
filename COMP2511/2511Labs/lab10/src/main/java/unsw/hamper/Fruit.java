package unsw.hamper;

public abstract class Fruit extends Item{
    private String name;

    public Fruit(String name){
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        Fruit other = (Fruit) obj;
        return name.equals(other.name);
    }

    @Override
    public String toString(){
        return super.toString()+" name="+name;
    }
}
