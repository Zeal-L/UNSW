package unsw.jql.v2;

import java.util.Objects;

public class Fruit {
    private final String type;
    private final String color;
    private final int age;

    public Fruit(String type, String color, int age) {
        this.type = type;
        this.color = color;
        this.age = age;
    }

    public int getAge() {
        return age;
    }

    public String getColor() {
        return color;
    }

    public String getType() {
        return type;
    }

    @Override
    public String toString() {
        return "Fruit [age=" + age + ", color=" + color + ", type=" + type + "]";
    }

    @Override
    public int hashCode() {
        return Objects.hash(age, color, type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Fruit other = (Fruit) obj;
        return age == other.age && Objects.equals(color, other.color) && Objects.equals(type, other.type);
    }
}
