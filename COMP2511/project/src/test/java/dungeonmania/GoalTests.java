package dungeonmania;

import static dungeonmania.TestUtils.getGoals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dungeonmania.DungeonManiaController;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.util.Direction;


public class GoalTests {
    @Test
    @DisplayName("Test if win after move to exit")
    public void testExitGoal() {
        DungeonManiaController dmc = new DungeonManiaController();
        dmc.newGame("d_movementTest_testMovementDown", "c_movementTest_testMovementDown");

        // move player downward to Exit
        dmc.tick(Direction.DOWN);
        String actual = dmc.tick(Direction.DOWN).getGoals();
        
        // assert after win
        assertEquals("", actual);
    }

    @Test
    @DisplayName("Test if win after collect the Treasure")
    public void testCollectTreasureGoal() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_goalTest_collectsingle", "c_movementTest_testMovementDown");

        assertTrue(getGoals(res).contains(":treasure"));

        // move player downward to Treasure
        dmc.tick(Direction.DOWN);
        String actual = dmc.tick(Direction.DOWN).getGoals();
        // assert after win
        assertEquals("", actual);
    }

    @Test
    @DisplayName("Test if win after collect the Treasure and move to exit")
    public void testCollectTreasureAndExitGoal() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_goalTest_collectAndExit", "c_movementTest_testMovementDown");

        assertTrue(getGoals(res).contains(":treasure"));
        assertTrue(getGoals(res).contains(":exit"));

        // move player downward to Treasure
        res = dmc.tick(Direction.DOWN);
        assertFalse(getGoals(res).contains(":treasure"));
        assertTrue(getGoals(res).contains(":exit"));

        String actual = dmc.tick(Direction.DOWN).getGoals();
        // assert after win
        assertEquals("", actual);
    }

    @Test
    @DisplayName("Test if win after collect the Treasure")
    public void testCollectTreasureOrExitGoal() {
        DungeonManiaController dmc = new DungeonManiaController();
        DungeonResponse res = dmc.newGame("d_goalTest_collectOrExit", "c_movementTest_testMovementDown");

        assertTrue(getGoals(res).contains(":treasure"));
        assertTrue(getGoals(res).contains(":exit"));

        String actual = dmc.tick(Direction.DOWN).getGoals();
        // assert after win
        assertEquals("", actual);
    }

}
