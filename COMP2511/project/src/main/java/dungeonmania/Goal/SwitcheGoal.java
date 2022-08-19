package dungeonmania.Goal;

import dungeonmania.Game;
import dungeonmania.StaticEntities.FloorSwitch;

public class SwitcheGoal extends GoalComponent {
    
    protected SwitcheGoal(String goalInfo) {
        super(goalInfo);
    }

    @Override
    public String toString(){
        
        return ! isComplete() ? getGoalInfo() : "";
    }
    
    public boolean isComplete() {
        return Game.getGame().getEntitiesByInstance(FloorSwitch.class)
                .stream()
                .allMatch(FloorSwitch::checkIsOn);
    }
}
