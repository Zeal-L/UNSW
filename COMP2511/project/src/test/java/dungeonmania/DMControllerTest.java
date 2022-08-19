package dungeonmania;

import static dungeonmania.TestUtils.getEntities;
import static dungeonmania.TestUtils.getPlayer;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.exceptions.InvalidActionException;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class DMControllerTest {
    @Test
    @DisplayName("test new game Exception")
    void testNewGameException() {
        DungeonManiaController dmc = new DungeonManiaController();
        assertThrows(IllegalArgumentException.class, () -> dmc.newGame("", ""));
        assertThrows(IllegalArgumentException.class, () -> dmc.newGame("d_DMCtest", ""));
        assertThrows(IllegalArgumentException.class, () -> dmc.newGame("", "c_spiderTest_basicMovement"));
    }

    @Test
    @DisplayName("test getDungeonResponseModel Exception")
    void testgetDungeonResponseModelException() {
        DungeonManiaController dmc = new DungeonManiaController();
         DungeonResponse expect = dmc.newGame("d_DMCtest", "c_DMCtest");
         assertEquals(expect.getEntities(), dmc.getDungeonResponseModel().getEntities());
    }

    @Test
    @DisplayName("test tick temUsedId")
    void testTickTemUsedId() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DMCtest", "c_DMCtest");
        String swordId = getEntities(game, "sword").get(0).getId();
        String bombId = getEntities(game, "bomb").get(0).getId();
        String arrowId = getEntities(game, "arrow").get(0).getId();
        String woodId = getEntities(game, "wood").get(0).getId();
        String invisibilityPotionId = getEntities(game, "invisibility_potion").get(0).getId();
        String invincibilityPotionId = getEntities(game, "invincibility_potion").get(0).getId();
        String keyId = getEntities(game, "key").get(0).getId();
        String treasureId = getEntities(game, "treasure").get(0).getId();
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(""));
        assertThrows(InvalidActionException.class, () -> dmc.tick(bombId));
        assertThrows(InvalidActionException.class, () -> dmc.tick(invisibilityPotionId));
        assertThrows(InvalidActionException.class, () -> dmc.tick(invincibilityPotionId));
        dmc.tick(Direction.RIGHT);
        dmc.tick(Direction.UP);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(""));
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(swordId));
        assertDoesNotThrow(() -> dmc.tick(bombId));
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(arrowId));
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(woodId));
        assertDoesNotThrow(() -> dmc.tick(invisibilityPotionId));
        assertDoesNotThrow(() -> dmc.tick(invincibilityPotionId));
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(keyId));
        assertThrows(IllegalArgumentException.class, () -> dmc.tick(treasureId));
    }

    @Test
    @DisplayName("test tick movement")
    void testTickMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DMCtest", "c_DMCtest");
        assertEquals(new Position(1,2),getPlayer(dmc.tick(Direction.DOWN)).get().getPosition());
        assertEquals(new Position(1,1),getPlayer(dmc.tick(Direction.UP)).get().getPosition());
        assertEquals(new Position(2,1),getPlayer(dmc.tick(Direction.RIGHT)).get().getPosition());
        assertEquals(new Position(1,1),getPlayer(dmc.tick(Direction.LEFT)).get().getPosition());
    }

    @Test
    @DisplayName("test build")
    void testBuild() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DMCtest", "c_DMCtest");
        assertThrows(IllegalArgumentException.class, () -> dmc.build(""));
        assertThrows(IllegalArgumentException.class, () -> dmc.build("sword"));
        assertThrows(IllegalArgumentException.class, () -> dmc.build("bomb"));
        assertThrows(InvalidActionException.class, () -> dmc.build("bow"));
        assertThrows(InvalidActionException.class, () -> dmc.build("shield"));
        dmc.tick(Direction.RIGHT);
        dmc.tick(Direction.UP);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        assertThrows(IllegalArgumentException.class, () -> dmc.build(""));
        assertThrows(IllegalArgumentException.class, () -> dmc.build("sword"));
        assertThrows(IllegalArgumentException.class, () -> dmc.build("bomb"));
        assertDoesNotThrow(() -> dmc.build("bow"));
        assertDoesNotThrow(() -> dmc.build("shield"));
    }

    @Test
    @DisplayName("test destroy zombie_toast_spawner")
    void Testinteract_zombie_toast_spawner() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DMCtest_testinteract_mercenary", "c_DMCtest");
        String zombieToastSpawnerId = getEntities(game, "zombie_toast_spawner").get(0).getId();
        assertThrows(IllegalArgumentException.class, () -> dmc.interact("kjgkfglkjhgkjh"));
        assertThrows(InvalidActionException.class, () -> dmc.interact(zombieToastSpawnerId));// the player does not have a weapon
        dmc.tick(Direction.RIGHT);
        assertThrows(InvalidActionException.class, () -> dmc.interact(zombieToastSpawnerId)); //player is not cardinally adjacent to the spawner
        dmc.tick(Direction.LEFT);
        assertDoesNotThrow(() -> dmc.interact(zombieToastSpawnerId));
    }

    @Test
    @DisplayName("test bribing mercenary")
    void Testinteract_bribing_mercenary() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_DMCtest_testinteract_bribingMercenary", "c_DMCtest");
        String mercenaryId = getEntities(game, "mercenary").get(0).getId();
        assertThrows(IllegalArgumentException.class, () -> dmc.interact("kjgkfglkjhgkjh"));
        assertThrows(InvalidActionException.class, () -> dmc.interact(mercenaryId));
        dmc.tick(Direction.DOWN);
        assertThrows(InvalidActionException.class, () -> dmc.interact(mercenaryId));
        dmc.tick(Direction.DOWN);
        assertThrows(InvalidActionException.class, () -> dmc.interact(mercenaryId));
        dmc.tick(Direction.UP);
        assertDoesNotThrow(() -> dmc.interact(mercenaryId));
    }
}
