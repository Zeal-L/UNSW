package dungeonmania;

import static dungeonmania.TestUtils.countEntityOfType;
import static dungeonmania.TestUtils.getEntitiesStream;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.util.Direction;

public class ZombieSpawnerTests {
    @Test
    @DisplayName("Basic Test Zombie Spawn")
    public void testZombieSpawn() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_zombiesSpawnerTest", "c_zombiesSpawnerTest");
        assertEquals(1, countEntityOfType(dmc.tick(Direction.UP),"zombie_toast")); //zombie_toast_spawner and zombie_toast
        assertEquals(2, countEntityOfType(dmc.tick(Direction.UP),"zombie_toast"));
        assertEquals(3, countEntityOfType(dmc.tick(Direction.UP),"zombie_toast"));
        assertEquals(4, countEntityOfType(dmc.tick(Direction.UP),"zombie_toast"));
    }
    @Test
    @DisplayName("Test Zombie Spawn surrounded by walls")
    public void testZombieSpawnSurroundedByWalls() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_zombiesSpawnerTest_SurroundedByWallsTest", "c_zombiesSpawnerTest");
        assertEquals(0, countEntityOfType(dmc.tick(Direction.UP),"zombie_toast"));
        assertEquals(0, countEntityOfType(dmc.tick(Direction.DOWN),"zombie_toast"));
        assertEquals(0, countEntityOfType(dmc.tick(Direction.LEFT),"zombie_toast"));
        assertEquals(0, countEntityOfType(dmc.tick(Direction.RIGHT),"zombie_toast"));
    }

    @Test
    @DisplayName("Test Zombie Spawn can be destroy by weapons")
    public void testZombieSpawnDestroyedByWeapons() {
        DungeonManiaController dmc = new DungeonManiaController();
        String SpawnerId = getEntitiesStream(dmc.newGame("d_zombiesSpawnerTest_destroy", "c_zombiesDestoryTest"), "zombie_toast_spawner").findFirst().get().getId();
        assertEquals(1, countEntityOfType(dmc.tick(Direction.DOWN),"zombie_toast_spawner")); //take weapons
        dmc.tick(Direction.UP);//back to spawner
        assertDoesNotThrow(() -> assertEquals(0, countEntityOfType(dmc.interact(SpawnerId),"zombie_toast_spawner"))); //zombie_toast_spawner should be destroyed
    }
}
