package Behavioral.VisitorPattern.visitor;

import Behavioral.VisitorPattern.shapes.Circle;
import Behavioral.VisitorPattern.shapes.CompoundShape;
import Behavioral.VisitorPattern.shapes.Dot;
import Behavioral.VisitorPattern.shapes.Rectangle;

public interface Visitor {
    String visitDot(Dot dot);

    String visitCircle(Circle circle);

    String visitRectangle(Rectangle rectangle);

    String visitCompoundGraphic(CompoundShape cg);
}