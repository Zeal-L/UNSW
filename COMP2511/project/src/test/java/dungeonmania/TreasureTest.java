package dungeonmania;

import static org.junit.jupiter.api.Assertions.assertEquals;

import static dungeonmania.TestUtils.getPlayer;
import static dungeonmania.TestUtils.getInventory;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.EntityResponse;
import dungeonmania.response.models.ItemResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;
public class TreasureTest {
    @Test
    @DisplayName("Test the treasure exists in dungeon")
    public void testTreasureExist() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_treasureTest", "c_movementTest_testMovementDown");
        
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("treasure")).findFirst().get();
        assertEquals("treasure", curr.getType());
    }

    @Test
    @DisplayName("Test the treasure's position")
    public void testTreasurePosition() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_treasureTest", "c_movementTest_testMovementDown");
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("treasure")).findFirst().get();
        assertEquals(new Position(1, 2), curr.getPosition());
    }

    @Test
    @DisplayName("Test the if the treasure is collectable")
    public void testTreasurePickUp() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_treasureTest", "c_movementTest_testMovementDown");
        init =  dmc.tick(Direction.DOWN);
        assertEquals(new Position(1, 2), getPlayer(init).get().getPosition());
        List<ItemResponse> curr_treasure_item = getInventory(init, "treasure");
        assertEquals(1, curr_treasure_item.size());


        List<EntityResponse> currTreasure = init.getEntities().stream().filter(e->e.getType().equals("treasure")).collect(Collectors.toList());
        assertEquals(0, currTreasure.size());
    }
}
