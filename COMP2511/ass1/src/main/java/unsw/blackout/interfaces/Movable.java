package unsw.blackout.interfaces;

import unsw.utils.Angle;

public interface Movable {
    int getSpeed();
    Angle getPosition();
    void setPosition(Angle position);
    double getHeight();
    void setHeight(double height);
}
