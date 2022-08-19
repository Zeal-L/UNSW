package dungeonmania;

import static dungeonmania.TestUtils.getPlayer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class PortalTests {
    /**
     * #       0        1        2        3        4
     * 0      [ ]     p_Blue    [ ]     PLAYER   p_Red
     * 1      [ ]      [ ]      [ ]      [ ]      [ ]
     * 2      [ ]     p_Blue    [ ]      [ ]      [ ]
     * 3      [ ]      [ ]      [ ]     p_Red     [ ]
     * 4      [ ]      [ ]      [ ]      [ ]      [ ]
     */
    @Test
    @DisplayName("Test player can go through and be teleported by portal")
    public void testPortalTeleport() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_PortalsTest", "c_movementTest_testMovementDown");

        assertEquals(new Position(3, 0), getPlayer(game).get().getPosition());
        // game = dmc.tick(Direction.RIGHT);
        assertEquals(new Position(4, 3), getPlayer(dmc.tick(Direction.RIGHT)).get().getPosition());
        
        // dmc.tick(Direction.LEFT);
        assertEquals(new Position(3, 0), getPlayer(dmc.tick(Direction.LEFT)).get().getPosition());
        
        game = dmc.tick(Direction.LEFT);
        // dmc.tick(Direction.LEFT);
        assertNotEquals(getPlayer(game).get().getPosition(), getPlayer(dmc.tick(Direction.LEFT)).get().getPosition());
    }

    /**
     * #       0        1        2        3        4        5        6
     * 0      [ ]      [ ]      [ ]     PLAYER   p_Red     [ ]      [ ]
     * 1      [ ]     p_Blue    [ ]      [ ]      [ ]     p_Grey    [ ]
     * 2      [ ]      [ ]      [ ]     p_Blue    [ ]      [ ]      [ ]
     * 3      [ ]      [ ]    p_Green   p_Red    p_Grey    [ ]      [ ]
     * 4      [ ]      [ ]      [ ]    p_Yellow   [ ]      [ ]      [ ]
     * 5      [ ]    p_Green    [ ]      [ ]      [ ]    p_Yellow   [ ]
     */
    @Test
    @DisplayName("Test player can go through and be teleported by nested portal")
    public void testPortalTeleportNested() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_PortalsAdvanced", "c_movementTest_testMovementDown");

        assertEquals(new Position(3, 0), getPlayer(game).get().getPosition());
        game = dmc.tick(Direction.RIGHT);
        assertEquals(new Position(6, 1), getPlayer(game).get().getPosition());
        
        game = dmc.tick(Direction.LEFT);
        assertEquals(new Position(3, 0), getPlayer(game).get().getPosition());

        dmc.tick(Direction.LEFT);
        dmc.tick(Direction.LEFT);
        game = dmc.tick(Direction.DOWN);
        assertEquals(new Position(4, 1), getPlayer(game).get().getPosition());
    }


    /**
     * #       0        1        2        3        4
     * 0      [ ]      [ ]     p_Blue   PLAYER   p_Red
     * 1      [ ]      [ ]      [ ]      [ ]      [ ]
     * 2      wall   boluder   p_Blue    [ ]      [ ]
     * 3      [ ]      [ ]      [ ]     p_Red     wall
     * 4      [ ]      [ ]      [ ]      [ ]      [ ]
     */
    @Test
    @DisplayName("Test player can not be teleported with an obstacle behind portal")
    public void testPortalTeleportWithObstacles() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_PortalsTest", "c_movementTest_testMovementDown");

        assertEquals(new Position(3, 0), getPlayer(game).get().getPosition());
        game = dmc.tick(Direction.RIGHT);
        assertEquals(new Position(4, 3), getPlayer(game).get().getPosition());

        dmc.tick(Direction.LEFT);
        game = dmc.tick(Direction.LEFT);
        assertEquals(new Position(2, 0), getPlayer(game).get().getPosition());
    }
}
