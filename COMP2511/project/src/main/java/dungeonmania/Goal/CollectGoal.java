package dungeonmania.Goal;

import dungeonmania.Game;
import dungeonmania.CollectableEntities.Treasure;

public class CollectGoal extends GoalComponent {
    private final int treasureGoal;
    
    protected CollectGoal(String goalInfo, int treasureGoal) {
        super(goalInfo);
        this.treasureGoal = treasureGoal;
    }

    @Override
    public String toString(){
        
        return ! isComplete() ? getGoalInfo() : "";
    }
    
    public boolean isComplete() {
        return treasureGoal <= Game.getGame().getPlayer()
                                    .getBackpack()
                                    .stream()
                                    .filter(e -> e instanceof Treasure)
                                    .count();
    }
}

