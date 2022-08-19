package dungeonmania;

import dungeonmania.exceptions.InvalidActionException;

public interface Interactive {
    void interact() throws InvalidActionException;
}
