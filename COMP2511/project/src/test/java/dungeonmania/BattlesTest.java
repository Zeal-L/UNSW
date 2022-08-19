package dungeonmania;

import static dungeonmania.TestUtils.getEntities;
import static dungeonmania.TestUtils.getInventory;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.response.models.BattleResponse;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.ItemResponse;
import dungeonmania.util.Direction;

public class BattlesTest {
    @Test
    @DisplayName("Test the basic battle")
    public void testBasicBattle() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_BattleTest_mercenary", "c_Battle");
        DungeonResponse after_Battle = dmc.tick(Direction.DOWN);
        BattleResponse battle = after_Battle.getBattles().get(0);
        assertEquals(1,after_Battle.getBattles().size());
        assertTrue(battle.getEnemy().startsWith("mercenary"));
        assertEquals(5,battle.getInitialEnemyHealth());
        assertEquals(10,battle.getInitialPlayerHealth());
        assertEquals(new ArrayList<>(),battle.getRounds().get(0).getWeaponryUsed());
        assertEquals(-2,battle.getRounds().get(0).getDeltaEnemyHealth());
        assertEquals(-0.1,battle.getRounds().get(0).getDeltaCharacterHealth());
        assertEquals(-2,battle.getRounds().get(1).getDeltaEnemyHealth());
        assertEquals(-0.1,battle.getRounds().get(1).getDeltaCharacterHealth());
        assertEquals(-2,battle.getRounds().get(2).getDeltaEnemyHealth());
        assertEquals(-0.1,battle.getRounds().get(2).getDeltaCharacterHealth());
    }

    @Test
    @DisplayName("Test the battle with Invincibility")
    public void testInvincibilityBattle() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_BattleTest_Invincibility", "c_BattleTest_Invincibility");
        String invId = getInventory(dmc.tick(Direction.RIGHT),"invincibility_potion").get(0).getId();
        assertDoesNotThrow(()->dmc.tick(invId));
        dmc.tick(Direction.RIGHT);
        DungeonResponse after_Battle = assertDoesNotThrow(()->dmc.tick(Direction.RIGHT));
        assertEquals(1,after_Battle.getBattles().size());
        assertEquals(1,after_Battle.getBattles().get(0).getRounds().size());
        assertEquals("invincibility_potion",after_Battle.getBattles().get(0).getRounds().get(0).getWeaponryUsed().get(0).getType());
        assertEquals(new ArrayList<>(), getEntities(after_Battle,"mercenary"));
        assertEquals(1, getEntities(after_Battle,"player").size());
    }

    @Test
    @DisplayName("Test the battle with Sword")
    public void testBattleSword() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_BattleTest_sword", "c_BattleTest_sword");
        String invId = getEntities(res,"sword").get(0).getId();//pick up sword
        dmc.tick(Direction.UP);
        DungeonResponse after_Battle = dmc.tick(Direction.DOWN);
        BattleResponse battle = after_Battle.getBattles().get(0);
        assertTrue(battle.getEnemy().startsWith("mercenary"));
        assertEquals(1,battle.getRounds().get(0).getWeaponryUsed().size());
        assertEquals(-3,battle.getRounds().get(0).getDeltaEnemyHealth());
        assertEquals(-0.1,battle.getRounds().get(0).getDeltaCharacterHealth());
    }

    @Test
    @DisplayName("Test the battle with multiple weapon and invincibility_potion")
    public void testBattleWithWeaponAndInvincibility() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_battleTest_adv", "c_BattleTest_Weapon");
        for(int i = 0; i < 13; i++) {
            res = dmc.tick(Direction.RIGHT);
        }
        String invId = getInventory(res,"sword").get(0).getId();
        String bow = assertDoesNotThrow(()->getInventory(dmc.build("bow"),"bow").get(0).getId());
        String shield = assertDoesNotThrow(()->getInventory(dmc.build("shield"),"shield").get(0).getId());
        String invpid = getInventory(res,"invincibility_potion").get(0).getId();
        assertDoesNotThrow(()->dmc.tick(invpid));
        res = dmc.tick(Direction.RIGHT);
        assertEquals(1,res.getBattles().size());
        assertEquals(1,res.getBattles().get(0).getRounds().size());
        assertEquals(4,res.getBattles().get(0).getRounds().get(0).getWeaponryUsed().size());
        assertEquals(Stream.of(invId,bow,shield,invpid).sorted().collect(Collectors.toList()), res.getBattles().get(0).getRounds().get(0).getWeaponryUsed().stream().map(ItemResponse::getId).sorted().collect(Collectors.toList()));
        assertEquals(Stream.of("sword","bow","shield","invincibility_potion").sorted().collect(Collectors.toList()), res.getBattles().get(0).getRounds().get(0).getWeaponryUsed().stream().map(ItemResponse::getType).sorted().collect(Collectors.toList()));
        assertEquals(0, res.getBattles().get(0).getRounds().get(0).getDeltaCharacterHealth());
        assertEquals(-500000000, res.getBattles().get(0).getRounds().get(0).getDeltaEnemyHealth());
    }

    @Test
    @DisplayName("Test the battle with multiple weapon and invisibility_potion")
    public void testBattleWithWeaponAndInvisibility() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_battleTest_adv", "c_BattleTest_Weapon");
        for(int i = 0; i < 13; i++) {
            res = dmc.tick(Direction.RIGHT);
        }
        String invId = getInventory(res,"sword").get(0).getId();
        String bow = assertDoesNotThrow(()->getInventory(dmc.build("bow"),"bow").get(0).getId());
        String shield = assertDoesNotThrow(()->getInventory(dmc.build("shield"),"shield").get(0).getId());
        String invpid = getInventory(res,"invisibility_potion").get(0).getId();
        assertDoesNotThrow(()->dmc.tick(invpid));
        res = dmc.tick(Direction.RIGHT);
        assertEquals(0,res.getBattles().size());
    }
}
