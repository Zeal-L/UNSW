package dungeonmania.CollectableEntities;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.DungeonManiaController;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.util.Direction;


public class PotionTests {
    @Test
    @DisplayName("Test adding to bag")
    public void testaddToBag() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("advanced", "c_movementTest_testMovementDown");
        
        res = dmc.tick(Direction.RIGHT);
        assertTrue(res.getInventory().get(0).getType().startsWith("invincibility_potion"));
        res = dmc.tick(Direction.RIGHT);
        assertTrue(res.getInventory().get(1).getType().startsWith("invisibility_potion"));
        
    }
}
