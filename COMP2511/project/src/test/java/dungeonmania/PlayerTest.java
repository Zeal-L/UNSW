package dungeonmania;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.EntityResponse;
import dungeonmania.response.models.ItemResponse;
import dungeonmania.util.Direction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static dungeonmania.TestUtils.getEntities;
import static dungeonmania.TestUtils.getPlayer;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PlayerTest {
    @Test
    @DisplayName("Test player move")
    public void testMovement() {
        DungeonManiaController dmc = new DungeonManiaController();
        EntityResponse player = getPlayer(dmc.newGame("d_PlayerTest_basicmove", "c_Playertest")).get();
        assertEquals(player.getPosition(),getPlayer(dmc.tick(Direction.UP)).get().getPosition());//wall
        assertEquals(player.getPosition(),getPlayer(dmc.tick(Direction.UP)).get().getPosition());//wall
        assertEquals(player.getPosition().translateBy(Direction.DOWN),getPlayer(dmc.tick(Direction.DOWN)).get().getPosition());//wall
        assertEquals(player.getPosition(),getPlayer(dmc.tick(Direction.UP)).get().getPosition());
    }

    @Test
    @DisplayName("Test player Collection")
    public void testCollection() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_PlayerTest_Collection", "c_Playertest");
        assertEquals(new ArrayList<>(), res.getInventory());
        List<String> expected = new ArrayList<>();
        expected.add("treasure");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("key");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("invincibility_potion");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("invisibility_potion");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("wood");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("arrow");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("bomb");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
        expected.add("sword");
        assertEquals(expected, dmc.tick(Direction.DOWN).getInventory().stream().map(ItemResponse::getType).collect(Collectors.toList()));
    }

    @Test
    @DisplayName("Test player fight with mercenary")
    public void testFight() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_PlayerTest_FightMercenary", "c_Playertest");
        assertEquals(1, getEntities(dmc.tick(Direction.LEFT), "mercenary").size());//mercenary should be dead
        assertEquals(new ArrayList<>(), getEntities(dmc.tick(Direction.LEFT), "player"));//player should be dead
    }

    @Test
    @DisplayName("Test player fight with Invincibility")
    public void testUseInvincibility() {
        DungeonManiaController dmc = new DungeonManiaController();
        String invincibility_potion_id = getEntities(dmc.newGame("d_PlayerTest_FightMercenary", "c_Playertest"),"invincibility_potion").get(0).getId();
        dmc.tick(Direction.RIGHT);
        dmc.tick(Direction.RIGHT);
        assertDoesNotThrow(() -> dmc.tick(invincibility_potion_id));
        dmc.tick(Direction.LEFT);
        dmc.tick(Direction.LEFT);
        dmc.tick(Direction.LEFT);
        dmc.tick(Direction.LEFT);
        dmc.tick(Direction.LEFT);
        assertEquals("player", getEntities(dmc.tick(Direction.LEFT), "player").get(0).getType());//player not should be dead
        assertEquals("player", getEntities(dmc.tick(Direction.LEFT), "player").get(0).getType());//player not should be dead
        assertEquals(new ArrayList<>(), getEntities(dmc.getDungeonResponseModel(), "mercenary"));//all mercenary should be dead
    }

}
