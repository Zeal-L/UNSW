package dungeonmania.Goal;



public abstract class GoalComponent implements Goal {
    private final String goalInfo;

    protected GoalComponent(String goalInfo) {
        this.goalInfo = ":" + goalInfo;
    }

    protected String getGoalInfo() {
        return goalInfo;
    }
}
