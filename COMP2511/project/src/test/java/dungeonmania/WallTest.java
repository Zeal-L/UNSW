package dungeonmania;

import static org.junit.jupiter.api.Assertions.assertEquals;

import static dungeonmania.TestUtils.getPlayer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.EntityResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class WallTest {
    @Test
    @DisplayName("Test the wall's position")
    public void testWallPosition() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_wallTest", "c_movementTest_testMovementDown");
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("wall")).findFirst().get();
        assertEquals("wall", curr.getType());
    }

    @Test
    @DisplayName("Test the player cannot move through the wall")
    public void testWallCannotMove() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_wallTest", "c_movementTest_testMovementDown");
        init =  dmc.tick(Direction.DOWN);
        assertEquals(new Position(1, 1), getPlayer(init).get().getPosition());
    }

    
}
