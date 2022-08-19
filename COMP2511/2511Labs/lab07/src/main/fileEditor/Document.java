package fileEditor;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

import javax.swing.JFileChooser;
import javax.swing.JInternalFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileFilter;

/**
 * Holds text and performs functionality - save, open etc.
 */
@SuppressWarnings({"serial"})
public abstract class Document extends JInternalFrame {

	/**
	 * Creates a new Document object with the given
	 * title and coordinates
	 * 
	 * @param title
	 *				The String title of the new Document object 
	 * @param x
	 *				The horizontal position on screen of the new Document
	 * @param y		
	 *				The vertical position on screen of the new Document
	 *
	 */
	public Document(String title, int x, int y) {
		super(title, true, true, true, true);
		textArea = new JTextArea(); //holds text
		JScrollPane internalScrollPane = new JScrollPane(textArea);
		super.getContentPane().add(internalScrollPane);
		this.setSize(200, 200); //small frame
		this.setLocation(x, y);
		this.saved = false;
		// listens to this document closing
		this.addInternalFrameListener(new DocumentListener(this)); 
		textArea.grabFocus();
		chooser = new JFileChooser();
		//factory method
		chooser.setFileFilter(this.createFileFilter());
		this.setVisible(true);
	}

	/**
	 * Opens a dialog box to select an file to be opened
	 * and reads the selected file into the current Document.
	 * 
	 * @return
	 *			A boolean value indicating whether
     *			a file has been opened or not
	 */
	public boolean open() {
		chooser.showOpenDialog(this.textArea);
		File choice = chooser.getSelectedFile();
		if (choice != null) {
			this.setTitle(choice.getAbsolutePath());
			textArea.setText("");
			try {
				textArea.read(new FileReader(choice), null);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		this.saved = true;
		textArea.grabFocus();
		return choice != null;
	}

	/**
	 * Saves text to a specified text file
	 */
	public void saveAs() {
		chooser.setDialogTitle("Save As - " + this.title);
		chooser.showSaveDialog(this.textArea);
		File choice = chooser.getSelectedFile();
		if (choice != null) {
			this.setTitle(choice.getAbsolutePath());
			save();
		}
		this.saved = true;
		textArea.grabFocus();
	}

	/**
	 * Saves the contents of the text area to a
	 * text file with the text area title as filename
	 */
	public void save() {
		try {
			textArea.write(new FileWriter(this.getTitle()));
		} catch (Exception e) { //ignore exception
		}
		textArea.grabFocus();
	}

	/**
	 * Indicates whether a Document has ever been saved.
	 *
	 * @return 
     *			A boolean indicating whether the current
	 *			Document object has been saved to file.
	 */
	public boolean saved() {
		return this.saved;
	}

	/**
	 * Copies the selected contents of the text area of this Document.
	 */
	public void copy() {
		this.textArea.copy();
		textArea.grabFocus();
	}

	/**
	 * Cuts the selected contents of the text area of this Document.
	 */
	public void cut() {
		this.textArea.cut();
		textArea.grabFocus();
	}
	
	/**
	 * Copies the contents of the clipboard 
	 * into the text area of this Document.
	 */
	public void paste() {
		this.textArea.paste();
		textArea.grabFocus();
	}
	
	/**
	 * Selects all of the contents of the text area of this Document.
	 */
	public void selectAll() {
		this.textArea.selectAll();
		textArea.grabFocus();
	}

	/**
	 * Adds the given text on a new line in the text area
	 *
	 * @param text
	 *				The String which is to be appended
	 *				to the text area on a line of its own.
	 */
	public void append(String text) {
		textArea.append("\n" + text + "\n");
	}
	
	protected abstract FileFilter createFileFilter();
	protected JTextArea textArea;
	private boolean saved;
	private JFileChooser chooser;
}