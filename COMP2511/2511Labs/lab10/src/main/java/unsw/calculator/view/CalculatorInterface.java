package unsw.calculator.view;

import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class CalculatorInterface extends JFrame {

    private JTextField field;
  
    /**
     * Creates a new CalculatorInterface object setting
     * up the calculator buttons and placing them appropriately
     * and making the calculator visible.
     */
    public CalculatorInterface()  {
        super("Calculator");

        // Display results, integers etc.
        field = new JTextField();
        this.getContentPane().add(field, "North");
        field.setEditable(false);
        field.setBackground(Color.white);

        // Used for entering numbers
        JPanel buttonPanel = new JPanel(new GridLayout(4, 4));

        // Listen to buttons
        ActionListener listener = new ButtonListener(this);

        // Buttons
        JButton button = new JButton("7");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("8");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("9");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("+");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("4");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("5");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("6");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("-");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("1");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("2");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("3");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("*");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("0");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("/");
        buttonPanel.add(button);
        button.addActionListener(listener);

        button = new JButton("=");
        buttonPanel.add(button);
        button.addActionListener(listener);

        this.getContentPane().add(buttonPanel, "Center");

        this.addWindowListener(new BasicWindowCloser());
        this.setResizable(false);
        this.pack();
        this.setVisible(true);
    }
    
    /**
     * Accesses the JTextField display of the calculator interface
     *
     * @return the JTextField display of the the calculator interface
     */
    public JTextField getField()  {
        return this.field;
    }
  
    /**
     * A Factory Method that returns a dummy evaluator at the moment
     *
     * @return a new DummyEvaluator object
     */
    public Evaluator getEvaluator(){
        return new DummyEvaluator();
    }
  
    public static void main(String[] args)  {
        CalculatorInterface calc = new CalculatorInterface();
    }  
}