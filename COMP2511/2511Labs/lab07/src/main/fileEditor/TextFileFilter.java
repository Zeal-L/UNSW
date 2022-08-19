package fileEditor;

import java.io.File;

import javax.swing.filechooser.FileFilter;

/**
 * For dialog box to filter files for display
 */

public class TextFileFilter extends FileFilter {

	/**
	 * Checks whether a given File object is a text file or a directory
	 *
	 * @param f The File object to be checked for acceptance.
	 * @return	A boolean value indicating whether the given file
	 *			is either a text file or a directory.
	 */
	public boolean accept(File f) {
		return f.getName().endsWith(".txt") || f.isDirectory();
	}

	/**
	 * Returns the description of text files
	 *
	 * @return The String "Text files"
	 */
	public String getDescription() {
		return "Text files";
	}
}