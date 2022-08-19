package unsw.calculator.view;

/*
 * Interface to evaluate an expression. 
 */
public interface Evaluator  {

    /**
     * Parses and evaluates a given expression.
     * @param expression
     * @return
     */
    public int evaluate(String expression);
  
}