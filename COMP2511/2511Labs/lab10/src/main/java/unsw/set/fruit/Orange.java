package unsw.set.fruit;

public class Orange implements Fruit {

    private String name;

    public Orange(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        Orange other = (Orange) obj;
        if (!name.equals(other.name)) return false;
        return true;
    }

}
