package dungeonmania.Goal;

import dungeonmania.Game;

public class DestroyGoal extends GoalComponent {
    private final int enemyGoal;

    protected DestroyGoal(String goalInfo, int enemyGoal) {
        super(goalInfo);
        this.enemyGoal = enemyGoal;
    }

    @Override
    public String toString(){
        
        return ! isComplete() ? getGoalInfo() : "";
    }
    
    public boolean isComplete() {
        return enemyGoal <= Game.getGame().getPlayer().getEnemiesKilled();
    }
}
