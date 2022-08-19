package dungeonmania;

import static org.junit.jupiter.api.Assertions.assertEquals;

import static dungeonmania.TestUtils.getPlayer;
import static dungeonmania.TestUtils.getInventory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.EntityResponse;
import dungeonmania.response.models.ItemResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class SwordTest {
    @Test
    @DisplayName("Test the sword exists in dungeon")
    public void testSwordExist() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_swordTest", "c_movementTest_testMovementDown");
        
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("sword")).findFirst().get();
        assertEquals("sword", curr.getType());
    }

    @Test
    @DisplayName("Test the sword's position")
    public void testSwordPosition() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_swordTest", "c_movementTest_testMovementDown");
        EntityResponse curr = init.getEntities().stream().filter(e->e.getType().equals("sword")).findFirst().get();
        assertEquals(new Position(1, 2), curr.getPosition());
    }

    @Test
    @DisplayName("Test the if the sword is collectable")
    public void testSwordPickUp() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse init = dmc.newGame("d_swordTest", "c_movementTest_testMovementDown");
        init =  dmc.tick(Direction.DOWN);
        assertEquals(new Position(1, 2), getPlayer(init).get().getPosition());
        List<ItemResponse> curr_sword_item = getInventory(init, "sword");
        assertEquals(1, curr_sword_item.size());
        List<EntityResponse> currSword = init.getEntities().stream().filter(e->e.getType().equals("arrow")).collect(Collectors.toList());
        assertEquals(new ArrayList<>(), currSword);
    }

}

