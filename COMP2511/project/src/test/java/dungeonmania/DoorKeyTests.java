package dungeonmania;

import static dungeonmania.TestUtils.getPlayer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.ItemResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class DoorKeyTests {
    /**
     * player   key1    door1
     * [  ]     door2   [  ]
     */
    @Test
    @DisplayName("Test the key can be collected")
    public void testKeyCollection() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DoorsKeysTest", "c_movementTest_testMovementDown");

        assertTrue(game.getInventory().size() == 0);

        game = dmc.tick(Direction.RIGHT);
        assertEquals(1, game.getInventory().size());
        assertEquals(new Position(2, 1), getPlayer(game).get().getPosition());

        ItemResponse temItem = game.getInventory().stream().filter(e -> e.getType().equals("key")).findFirst().get();
        assertEquals("key", temItem.getType());
    }
    
    
    @Test
    @DisplayName("Test the key can open the door")
    public void testKeyOpenDoor() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DoorsKeysTest", "c_movementTest_testMovementDown");

        assertTrue(game.getInventory().size() == 0);

        game = dmc.tick(Direction.RIGHT);
        ItemResponse temItem = game.getInventory().stream().filter(e -> e.getType().equals("key")).findFirst().get();
        assertEquals("key", temItem.getType());
        
        game = dmc.tick(Direction.RIGHT);
        assertTrue(game.getInventory().size() == 0);
        assertEquals(new Position(3, 1), getPlayer(game).get().getPosition());
    }


    @Test
    @DisplayName("Test the key can't open the door")
    public void testKeyCannotOpenDoor() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DoorsKeysTest", "c_movementTest_testMovementDown");

        assertTrue(game.getInventory().size() == 0);

        game = dmc.tick(Direction.RIGHT);
        game = dmc.tick(Direction.DOWN);
        assertTrue(game.getInventory().size() == 1);
        ItemResponse temItem = game.getInventory().stream().filter(e -> e.getType().equals("key")).findFirst().get();
        assertEquals("key", temItem.getType());
    }
}
