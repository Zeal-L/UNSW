package unsw.calculator.view;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Listens to closing of frame
 */
public class BasicWindowCloser extends WindowAdapter {

    /**
     * Exits the program when the window is closed.
     *
     * @param event
     *				the WindowEvent object indicating
    *				the window is being closed.
    */
    public void windowClosing(WindowEvent event)  {
        System.exit(0); // Kills the program when frame closed
    }

}