package graph;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import unsw.graph.Graph;

/**
 * Tests for the Graph exercise
 * 
 * @author Nick Patrikeos
 */
public class GraphTest {

    public Graph<String> setupGraphOfStrings() {
        Graph<String> graph = new Graph<String>();
        graph.addNode("A");
        graph.addNode("B");
        graph.addNode("C");
        graph.addNode("D");

        graph.addConnection("A", "B");
        graph.addConnection("B", "C");
        graph.addConnection("C", "A");
        graph.addConnection("C", "D");
        return graph;
    }

    public Graph<Integer> setupGraphOfIntegers() {
        Graph<Integer> graph = new Graph<Integer>();
        
        for (int i = 1; i <= 6; i++) {
            graph.addNode(i);
        }

        graph.addConnection(6, 4);
        graph.addConnection(4, 3);
        graph.addConnection(4, 5);
        graph.addConnection(5, 2);
        graph.addConnection(3, 2);
        graph.addConnection(2, 1);
        graph.addConnection(5, 1);
        return graph;
    }

    @Test
    public void testBFSStrings() {
        Graph<String> graph = setupGraphOfStrings();

        Iterator<String> iter1 = graph.breadthFirstIterator("A");
        assertEquals("A", iter1.next());
        assertEquals("B", iter1.next());
        assertEquals("C", iter1.next());
        assertEquals("D", iter1.next());
        assertFalse(iter1.hasNext());

        Iterator<String> iter2 = graph.breadthFirstIterator("B");
        assertEquals("B", iter2.next());
        assertEquals("A", iter2.next());
        assertEquals("C", iter2.next());
        assertEquals("D", iter2.next());
        assertFalse(iter2.hasNext());
    }

    @Test
    public void testBFSIntegers() {
        Graph<Integer> graph = setupGraphOfIntegers();

        Iterator<Integer> iter1 = graph.breadthFirstIterator(6);
        assertEquals(6, iter1.next());
        assertEquals(4, iter1.next());
        assertEquals(3, iter1.next());
        assertEquals(5, iter1.next());
        assertEquals(2, iter1.next());
        assertEquals(1, iter1.next());
        assertFalse(iter1.hasNext());

        Iterator<Integer> iter2 = graph.breadthFirstIterator(3);
        assertEquals(3, iter2.next());
        assertEquals(2, iter2.next());
        assertEquals(4, iter2.next());
        assertEquals(1, iter2.next());
        assertEquals(5, iter2.next());
        assertEquals(6, iter2.next());
        assertFalse(iter2.hasNext());
    }

    @Test
    public void testDFSStrings() {
        Graph<String> graph = setupGraphOfStrings();

        Iterator<String> iter1 = graph.depthFirstIterator("A");
        assertEquals("A", iter1.next());
        assertEquals("B", iter1.next());
        assertEquals("C", iter1.next());
        assertEquals("D", iter1.next());
        assertFalse(iter1.hasNext());

        Iterator<String> iter2 = graph.depthFirstIterator("B");
        assertEquals("B", iter2.next());
        assertEquals("A", iter2.next());
        assertEquals("C", iter2.next());
        assertEquals("D", iter2.next());
        assertFalse(iter2.hasNext());
    }

    @Test
    public void testDFSIntegers() {
        Graph<Integer> graph = setupGraphOfIntegers();

        Iterator<Integer> iter1 = graph.depthFirstIterator(6);
        assertEquals(6, iter1.next());
        assertEquals(4, iter1.next());
        assertEquals(3, iter1.next());
        assertEquals(2, iter1.next());
        assertEquals(1, iter1.next());
        assertEquals(5, iter1.next());
        assertFalse(iter1.hasNext());

        Iterator<Integer> iter2 = graph.depthFirstIterator(3);
        assertEquals(3, iter2.next());
        assertEquals(2, iter2.next());
        assertEquals(1, iter2.next());
        assertEquals(5, iter2.next());
        assertEquals(4, iter2.next());
        assertEquals(6, iter2.next());
        assertFalse(iter2.hasNext());
    }
}