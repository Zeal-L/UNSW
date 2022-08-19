package unsw.calculator.view;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Listens to the buttons of the calculator
 */
public class ButtonListener implements ActionListener {

    private CalculatorInterface calc;
    private boolean equalPressed;

    /**
     * Creates a new ButtonListener object
     *
     * @param calc
     *				the CalculatorInterface object to
    *				which this ButtonListener is attached
    */
    public ButtonListener(CalculatorInterface calc) {
        this.calc = calc;
        equalPressed = false;
    }

    /**
     * Sets the display to the number pressed or evaluates
     * the expression depending on what button has been clicked.
     *
     * @param e
     *			the ActionEvent object which determines
    *			which action should be taken
    */
    public void actionPerformed(ActionEvent e)  {
        if (isInteger(e.getActionCommand()))  {
            if (equalPressed) {
            calc.getField().setText("");
            equalPressed = false;
            }
            calc.getField().setText(calc.getField().getText() + e.getActionCommand());
        }
        else if (e.getActionCommand().equals("="))  {
            // Ask the evaluator to evaluate the expression
            calc.getField().setText("" + calc.getEvaluator().evaluate(calc.getField().getText()));
            this.equalPressed = true;
        }
        else  {
            calc.getField().setText(calc.getField().getText() + " " + e.getActionCommand() + " ");
            equalPressed = false;
        }
    }

    /**
     * Determines whether a given String is an integer.
     */
    private boolean isInteger(String integer) {
        try {
            Integer.parseInt(integer);
            return true;
        }
        catch (NumberFormatException nfe) {
            return false;
        }
    }
}
