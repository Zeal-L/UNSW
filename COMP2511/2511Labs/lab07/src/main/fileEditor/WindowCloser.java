package fileEditor;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JDesktopPane;
import javax.swing.JInternalFrame;

/**
 * Listens for the closing of a frame
 */
public class WindowCloser extends WindowAdapter {

	/**
	 * Creates a new WindowCloser object for the given
	 * JDesktopPane
	 *
	 * @param pane
	 *				The JDesktopPane which will be associated
	 *				with the new WindowCloser object.
	 *
	 */				
	public WindowCloser(JDesktopPane pane) {
		this.pane = pane;
	}

	/**
	 * Saves all open documents and exits the program
	 *
	 * @param event
	 *				The WindowEvent indicating that it is 
	 *				closing.
	 */
	public void windowClosing(WindowEvent event) {
		JInternalFrame[] frames = pane.getAllFrames();
		for (int i = 0; i < frames.length; i++) {
			((Document) frames[i]).saveAs();
		}
		System.exit(0);
	}
	
	private JDesktopPane pane;
}