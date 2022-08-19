package dungeonmania;

import static dungeonmania.TestUtils.getEntities;
import static dungeonmania.TestUtils.getInventory;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.exceptions.InvalidActionException;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.EntityResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;

public class MercenaryTest {
    @Test
    @DisplayName("Test mercenary basic move")
    public void testBasicMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        EntityResponse mercenary = getEntities(dmc.newGame("d_MercenaryTest_basicmove", "c_Mercenarytest"),"mercenary").get(0);
        EntityResponse moved = getEntities(dmc.tick(Direction.DOWN),"mercenary").get(0);
        assertNotEquals(mercenary.getPosition(),moved.getPosition());
        mercenary = moved;
        moved = getEntities(dmc.tick(Direction.DOWN),"mercenary").get(0);
        assertNotEquals(mercenary.getPosition(),moved.getPosition());
        mercenary = moved;
        moved = getEntities(dmc.tick(Direction.DOWN),"mercenary").get(0);
        assertNotEquals(mercenary.getPosition(),moved.getPosition());
    }
    @Test
    @DisplayName("Test mercenary shortest path move")
    public void testShortestMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        EntityResponse mercenary = getEntities(dmc.newGame("d_MercenaryTest_ShortestPath", "c_Mercenarytest"),"mercenary").get(0);
        for(int i = 0; i < 18; i++) {
            dmc.tick(Direction.RIGHT);
        }
        assertEquals(new ArrayList<>(),getEntities(dmc.tick(Direction.RIGHT),"mercenary"));//mercenary should fight the player and die
    }
    @Test
    @DisplayName("Test mercenary move Blind")
    public void testBlindMovement1() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_MercenaryTest_ShortestPath", "c_Mercenarytest");
        EntityResponse mercenary = getEntities(game,"mercenary").get(0);
        EntityResponse invisibility = getEntities(game,"invisibility_potion").get(0);
        dmc.tick(Direction.RIGHT);
        dmc.tick(Direction.RIGHT);
        assertDoesNotThrow(()->dmc.tick(invisibility.getId()));
        for(int i = 0; i < 16; i++) {
            dmc.tick(Direction.RIGHT);
        }
        assertEquals(1,getEntities(dmc.tick(Direction.RIGHT),"mercenary").size());//mercenary should not fight the player and die
    }
    @Test
    @DisplayName("Test mercenary runway move")
    public void testRunwayMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_MercenaryTest_runway", "c_Mercenarytest");
        EntityResponse mercenary = getEntities(game,"mercenary").get(0);
        EntityResponse invincibility = getEntities(game,"invincibility_potion").get(0);
        Position originP = getEntities(dmc.tick(Direction.DOWN),"mercenary").get(0).getPosition();
        Position afterP = getEntities(assertDoesNotThrow(()->dmc.tick(invincibility.getId())),"mercenary").get(0).getPosition();
        assertEquals(1,originP.getY()-afterP.getY());
    }
    @Test
    @DisplayName("Test mercenary move with Portal")
    public void testPortalMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse game = dmc.newGame("d_MercenaryTest_MoveWithPortal", "c_Mercenarytest");
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        dmc.tick(Direction.DOWN);
        EntityResponse mercenary = getEntities(dmc.getDungeonResponseModel(),"mercenary").get(0);
        assertEquals(new Position(7,8),mercenary.getPosition());
    }
    @Test
    @DisplayName("Test mercenary move Blind")
    public void testBlindMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_Mercenary_Blind", "c_Mercenary_Blind");
        DungeonResponse game = dmc.tick(Direction.UP);
        String invisibility = getInventory(game,"invisibility_potion").get(0).getId();
        dmc.tick(Direction.UP);
        assertDoesNotThrow(() -> dmc.tick(invisibility));
        for(int i = 0; i < 50; i++){
            assertEquals(1,getEntities(dmc.tick(Direction.UP),"mercenary").size());
        }
    }

    @Test
    @DisplayName("Test Bribed mercenary no way to player")
    public void testBribedMovementNoWay() {
        DungeonManiaController dmc = new DungeonManiaController();
        String mercenaryId = getEntities(dmc.newGame("d_MercenaryTest_NoWay", "c_Mercenary_Bribed"),"mercenary").get(0).getId();
        assertThrows(InvalidActionException.class,()->dmc.interact(mercenaryId));
        dmc.tick(Direction.DOWN);
        assertDoesNotThrow(()->dmc.interact(mercenaryId));
        for(int i = 0; i < 10; i++) {
            Position curr = getEntities(dmc.tick(Direction.UP),"mercenary").get(0).getPosition();
            assertEquals(getEntities(dmc.tick(Direction.UP),"mercenary").get(0).getPosition(), curr);
        }
    }


    @Test
    @DisplayName("Test Bribed mercenary has way to player")
    public void testBribedMovementHasWay() {
        DungeonManiaController dmc = new DungeonManiaController();
        String mercenaryId = getEntities(dmc.newGame("d_MercenaryTest_HasWay", "c_Mercenary_Bribed"),"mercenary").get(0).getId();
        assertThrows(InvalidActionException.class,()->dmc.interact(mercenaryId));
        dmc.tick(Direction.DOWN);
        assertDoesNotThrow(()->dmc.interact(mercenaryId));
        for(int i = 0; i < 10; i++) {
            Position curr = getEntities(dmc.tick(Direction.UP),"mercenary").get(0).getPosition();
            assertNotEquals(getEntities(dmc.tick(Direction.UP),"mercenary").get(0).getPosition(), curr);
        }
    }
}
