package dungeonmania.Goal;

import dungeonmania.Game;
import dungeonmania.StaticEntities.Exit;
import dungeonmania.util.Position;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.stream.Collectors;

public class GoalManager {
    private final Goal goal;
    private final int enemyGoal;
    private final int treasureGoal;
    private boolean hasExit;
    JSONObject goalInfo;

    public GoalManager(int enemyGoal, int treasureGoal, JSONObject goalInfo) {
        this.treasureGoal = treasureGoal;
        this.enemyGoal = enemyGoal;
        this.goalInfo = goalInfo;
        this.hasExit = false;
        goal = initializingGoal(goalInfo);
    }

    private Goal initializingGoal(JSONObject goalInfo) {
        String condition = goalInfo.getString("goal");
        if (condition.startsWith("AND")) {
            return createComposite(goalInfo.getJSONArray("subgoals"), true);
        } else if (condition.startsWith("OR")) {
            return createComposite(goalInfo.getJSONArray("subgoals"), false);
        }
        return createGoal(condition);
    }

    private Goal createComposite(JSONArray subgoals, boolean andOr) {
        Goal compsiteA = null;
        Goal compsiteB = null;
        String goalA = subgoals.getJSONObject(0).getString("goal");
        String goalB = subgoals.getJSONObject(1).getString("goal");

        if (subgoals.getJSONObject(0).has("subgoals")) {
            compsiteA = initializingGoal(subgoals.getJSONObject(0));
        }
        if (subgoals.getJSONObject(1).has("subgoals")) {
            compsiteB = initializingGoal(subgoals.getJSONObject(1));
        }
        

        return new AndOrComposite(  compsiteA != null ? compsiteA : createGoal(goalA), 
                                    compsiteB != null ? compsiteB : createGoal(goalB), 
                                    andOr);
    }

    private Goal createGoal(String goal) {
        if (goal.startsWith("exit")) {
            hasExit = true;
            return new ExitGoal(goal);
        }
        else if (goal.startsWith("treasure")) return new CollectGoal(goal, treasureGoal);
        else if (goal.startsWith("enemies")) return new DestroyGoal(goal, enemyGoal);
        else if (goal.startsWith("boulders")) return new SwitcheGoal(goal);
        else return null;
    }

    public String getGoal() {
        String goalStr = goal.toString();
        if(hasExit &&
                goalStr.contains(":exit") &&
                (goalStr.length() - goalStr.replace(":","").length() == 1) &&
                isExitComplete()) {
            return "";
        }
        return goalStr;
    }
    public boolean isExitComplete() {
        Position player = Game.getGame().getPlayer().getPosition();
        List<Position> exits = Game.getGame().getEntitiesByInstance(Exit.class)
                                    .stream()
                                    .map(Exit::getPosition)
                                    .collect(Collectors.toList());
        return exits.stream().anyMatch(p -> p.equals(player));
    }

}
