package dungeonmania.Goal;


public class AndOrComposite implements Goal {
    // True if the goal is and, Flse if the goal is or
    private final boolean andOr;
    private final Goal goalA;
    private final Goal goalB;
    
    protected AndOrComposite(Goal goalA, Goal goalB, boolean andOr) {
        this.goalA = goalA;
        this.goalB = goalB;
        this.andOr = andOr;
    }
    
    @Override
    public String toString(){

        StringBuilder sb = new StringBuilder();

    
        if (isComplete()) {
            return "";
        } else {
            goalBrackets(sb, goalA);
            if (! goalA.isComplete() && ! goalB.isComplete()) {
                sb.append(andOr ? " AND " : " OR ");
            }
            goalBrackets(sb, goalB);
            return sb.toString();
        }
        
    }

    private void goalBrackets(StringBuilder sb, Goal goal) {
        if (! goal.isComplete()) {
            if (goal instanceof GoalComponent) {
                sb.append(goal.toString());
            } else {
                AndOrComposite temp = (AndOrComposite) goal;
                if (temp.checkGoalA() || temp.checkGoalB()) {
                    sb.append(goal.toString());
                } else {
                    sb.append("(");
                    sb.append(goal.toString());
                    sb.append(")");
                }
            }
        }
    }

    @Override
    public boolean isComplete() {
        if(andOr) {
            return goalA.isComplete() && goalB.isComplete();
        } else {
            return goalA.isComplete() || goalB.isComplete();
        }
    }

    protected boolean checkGoalA() {
        return goalA.isComplete();
    }

    protected boolean checkGoalB() {
        return goalB.isComplete();
    }
}
