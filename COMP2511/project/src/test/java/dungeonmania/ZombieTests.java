package dungeonmania;

import static dungeonmania.TestUtils.getEntities;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;

import dungeonmania.response.models.DungeonResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.EntityResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class ZombieTests {
    @Test
    @DisplayName("basic Zombie move test")
    public void testZombiemove() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_zombiesTest_movement", "c_zombiesTest");
        EntityResponse zombie = getEntities(dmc.tick(Direction.UP),"zombie_toast").stream().findFirst().get();
        String zombieId = zombie.getId();
        Position originpos = zombie.getPosition();
        Position movedpos = getEntities(dmc.tick(Direction.UP),"zombie_toast").stream().filter(e -> e.getId().equals(zombieId)).findFirst().get().getPosition();
        assertTrue((originpos.getX()==movedpos.getX() && Math.abs(originpos.getY()- movedpos.getY())==1) || (originpos.getY()==movedpos.getY() && Math.abs(originpos.getX()- movedpos.getX())==1));//
    }

    @Test
    @DisplayName("Zombie movement constraints test")
    public void testZombieMovementConstraints() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_zombiesTest_SurroundedByWallsTest", "c_zombiesTest");
        Position Pos1 = getEntities(dmc.tick(Direction.UP),"zombie_toast").stream().findFirst().get().getPosition();
        for(int i = 0; i < 10; i++) {
            Position Pos2 = getEntities(dmc.tick(Direction.UP),"zombie_toast").stream().findFirst().get().getPosition();// zombie should not move
            assertEquals(Pos1, Pos2);
            Pos1 = Pos2;
        }
    }

    @Test
    @DisplayName("Zombie battle test")
    public void testZombieBattle() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_zombiesTest_battle", "c_zombiesTest");
        assertEquals(new ArrayList<>(),getEntities(dmc.tick(Direction.RIGHT),"zombie_toast"));// Zombie should be kill
    }

    @Test
    @DisplayName("Test Zombie runway move")
    public void testRunwayMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_ZombieTest_runway", "c_zombiesTest");
        EntityResponse invincibility = getEntities(game,"invincibility_potion").get(0);
        Position originP = getEntities(dmc.tick(Direction.DOWN),"zombie_toast").get(0).getPosition();
        Position afterP = getEntities(assertDoesNotThrow(()->dmc.tick(invincibility.getId())),"zombie_toast").get(0).getPosition();
        assertEquals(1,originP.getY()-afterP.getY());
    }
}
