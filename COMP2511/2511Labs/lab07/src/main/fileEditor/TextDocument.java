package fileEditor;

import javax.swing.filechooser.FileFilter;

/**
 * Represents a text document with a title and the initial location of the window
 */
@SuppressWarnings("serial")
public class TextDocument extends Document {

	/**
	 * Creates a new TextDocument object with the given
	 * title and coordinates.
	 *
	 * @param title
	 *				The String title of the new Document object 
	 * @param x
	 *				The horizontal position on screen of the new Document
	 * @param y		
	 *				The vertical position on screen of the new Document
	 *
	 */
	public TextDocument(String title, int x, int y) {
		super(title, x, y);
	}

	/**
	 * Returns a new TextFileFilter object
	 *
	 * @return A new FileFilter object
	 */
	protected FileFilter createFileFilter() {
		return new TextFileFilter();
	}

}
