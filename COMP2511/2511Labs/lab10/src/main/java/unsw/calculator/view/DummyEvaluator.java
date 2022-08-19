package unsw.calculator.view;

class DummyEvaluator implements Evaluator {

    /**
     * Ignores the String expression to be evaluated
     * and simply returns the integer 0
     * 
     * @ return the dummy value 0
     */
    public int evaluate(String expression){
        return 0;
    }
}