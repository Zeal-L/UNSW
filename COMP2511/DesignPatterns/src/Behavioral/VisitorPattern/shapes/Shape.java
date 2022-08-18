package Behavioral.VisitorPattern.shapes;

import Behavioral.VisitorPattern.visitor.Visitor;

public interface Shape {
    void move(int x, int y);
    void draw();
    String accept(Visitor visitor);
}