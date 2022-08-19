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

public class ArrowsTest {
    @Test
    @DisplayName("Test the arrow exists in dungeon")
    public void testArrowsExist() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_arrowsTest", "c_movementTest_testMovementDown");
        
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("arrow")).findFirst().get();
        assertEquals("arrow", curr.getType());
    }

    @Test
    @DisplayName("Test the arrow's position")
    public void testArrowsPosition() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_arrowsTest", "c_movementTest_testMovementDown");
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("arrow")).findFirst().get();
        assertEquals(new Position(1, 2), curr.getPosition());
    }

    @Test
    @DisplayName("Test the if the arrow is collectable")
    public void testArrowsPickUp() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_arrowsTest", "c_movementTest_testMovementDown");
        init =  dmc.tick(Direction.DOWN);
        assertEquals(new Position(1, 2), getPlayer(init).get().getPosition());
        List<ItemResponse> curr_arrows_item = getInventory(init, "arrow");
        assertEquals(1, curr_arrows_item.size());
        List<EntityResponse> currArrows = init.getEntities().stream().filter(e->e.getType().equals("arrow")).collect(Collectors.toList());
        assertEquals(0, currArrows.size());
    }

    
}
