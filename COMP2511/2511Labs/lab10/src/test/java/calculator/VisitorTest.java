package calculator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import unsw.calculator.model.EvaluatorVisitor;
import unsw.calculator.model.InFixPrintVisitor;
import unsw.calculator.model.PostFixPrintVisitor;
import unsw.calculator.model.Parser;
import unsw.calculator.model.Visitor;
import unsw.calculator.model.tree.TreeNode;

public class VisitorTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @BeforeEach
    public void setStreams() {
        System.setOut(new PrintStream(out));
    }

    @AfterEach
    public void restoreInitialStreams() {
        System.setOut(originalOut);
    }

    @Test
    public void testSimpleExpressionInfix() {
        Parser parser = new Parser("1 + 2 - 3 * 10 / 5"); // spaces are vital!!
	    TreeNode node = parser.parse();
        Visitor infixVisitor = new InFixPrintVisitor();
        node.accept(infixVisitor);

        assertEquals("((1 + 2) - ((3 * 10) / 5))", out.toString().strip());
    }

    @Test
    public void testSimpleExpressionPostfix() {
        Parser parser = new Parser("1 + 2 - 3 * 10 / 5"); // spaces are vital!!
	    TreeNode node = parser.parse();
        Visitor postfixVisitor = new PostFixPrintVisitor();
        node.accept(postfixVisitor);

        assertEquals("1 2 + 3 10 * 5 / -", out.toString().strip());
    }

    @Test
    public void testSimpleExpressionEvaluator() {
        Parser parser = new Parser("1 + 2 - 3 * 10 / 5"); // spaces are vital!!
	    TreeNode node = parser.parse();
        EvaluatorVisitor evaluatorVisitor = new EvaluatorVisitor();
        node.accept(evaluatorVisitor);

        assertEquals(-3, evaluatorVisitor.getValue());
    }

    @Test
    public void testSimpleExpression2Infix() {
        Parser parser = new Parser("10 + 10 / 2 * 3 - 6"); 
	    TreeNode node = parser.parse();
        Visitor infixVisitor = new InFixPrintVisitor();
        node.accept(infixVisitor);

        assertEquals("((10 + ((10 / 2) * 3)) - 6)", out.toString().strip());
    }   

    @Test
    public void testSimpleExpression2Postfix() {
        Parser parser = new Parser("10 + 10 / 2 * 3 - 6"); 
	    TreeNode node = parser.parse();
        Visitor postfixVisitor = new PostFixPrintVisitor();
        node.accept(postfixVisitor);
        assertEquals("10 10 2 / 3 * + 6 -", out.toString().strip());
        
    }

    @Test
    public void testSimpleExpression2Evaluator() {
        Parser parser = new Parser("10 + 10 / 2 * 3 - 6"); 
	    TreeNode node = parser.parse();
        EvaluatorVisitor evaluatorVisitor = new EvaluatorVisitor();
        node.accept(evaluatorVisitor);
        assertEquals(19, evaluatorVisitor.getValue());
    }


}