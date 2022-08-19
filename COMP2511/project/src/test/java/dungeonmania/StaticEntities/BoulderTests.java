package dungeonmania.StaticEntities;

import static dungeonmania.TestUtils.getEntities;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.DungeonManiaController;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class BoulderTests {
    @Test
    @DisplayName("Test the player can move boulder")
    public void testMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_boulderTest_single_boulder", "c_movementTest_testMovementDown");
        
        res = dmc.tick(Direction.UP);
        Position actual = getEntities(res, "boulder").get(0).getPosition();
        assertEquals(new Position(0, -2), actual);
        res = dmc.tick(Direction.UP);
        actual = getEntities(res, "boulder").get(0).getPosition();
        assertEquals(new Position(0, -2), actual);
    }
}
