package dungeonmania.Goal;



public class ExitGoal extends GoalComponent {
    
    protected ExitGoal(String goalInfo) {
        super(goalInfo);
    }
    @Override
    public String toString() {
        
        return ! isComplete() ? getGoalInfo() : "";
    }
    
    public boolean isComplete() {
        return false;
    }
}
