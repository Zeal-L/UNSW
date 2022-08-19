package unsw.set.fruit;

public class Apple implements Fruit {

    private String name;

    public Apple(String name) {
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
        Apple other = (Apple) obj;
        if (!name.equals(other.name)) return false;
        return true;
    }

}
