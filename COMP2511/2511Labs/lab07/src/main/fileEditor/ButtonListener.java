package fileEditor;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;

import javax.swing.JDesktopPane;
import javax.swing.JTextField;
import javax.swing.JInternalFrame;

import java.net.URL;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Listens to the buttons pressed on the tool bar
 */
public class ButtonListener implements ActionListener {

	private JDesktopPane pane;
    private int newWindowX, newWindowY, docCount;
    private JTextField textField;

	/**
	 * Creates a ButtonListener object
	 * 
	 * @param pane 
	 *				The JDesktopPane to which this
	 *				ButtonListener is attached.
	 *
	 */
	public ButtonListener(JDesktopPane pane) {
		this.pane = pane; 
		newWindowX = 0;
		newWindowY = 0;
		docCount = 0;
    }
    
    public void setTextField(JTextField textField) {
        this.textField = textField;
    }

	/**
	 * Performs the appropriate action depending
	 * on the type of event triggered.
	 *
	 * @param event 
	 *				The ActionEvent corresponding to
	 *				the button clicked
	 *
	 */
	public void actionPerformed(ActionEvent event) {
		TextDocument document, current = null;
		if (event.getActionCommand().equals("New")) { 
            // New button pressed
			document = new TextDocument("untitled" + docCount, newWindowX, newWindowY);
			this.addDocument(document);
			docCount++;
		} else if (event.getActionCommand().equals("Open")) { 
            // Open button pressed
            document = new TextDocument("", newWindowX, newWindowY); 
            // Dummy document
			if (document.open()){
				this.addDocument(document);
			}
		} else if (event.getActionCommand().equals("Save")) { 
            // Save button pressed
			current = this.getSelectedDocument();
			if (current != null){
				if (current.saved()){
					current.save();
				}else{
					current.saveAs();
				}
			}
		} else if (event.getActionCommand().equals("Save As")) {
            //Save As pressed
			current = this.getSelectedDocument();
			if (current != null){
				current.saveAs();
			}
		} else if (event.getActionCommand().equals("Copy")) {
            // Copy pressed
			current = this.getSelectedDocument();
			if (current != null){
				current.copy();
			}
		} else if (event.getActionCommand().equals("Paste")) {
            // Paste pressed
			current = this.getSelectedDocument();
			if (current != null){
				current.paste();
			}
		} else if (event.getActionCommand().equals("Cut")) {
            // Cut pressed
			current = this.getSelectedDocument();
			if (current != null){
				current.cut();
			}
		} else if (event.getActionCommand().equals("Select All")) {
            // Select all pressed
			current = this.getSelectedDocument();
			if (current != null){
				current.selectAll();
			}
		} else if (event.getActionCommand().equals("Go")) {
            openUrl(textField.getText());
        }
     }
     
     private void openUrl(String url) {
        URL page = null;
        try {
            page = new URL(url);
        } catch (MalformedURLException e) {}

        HttpURLConnection.setFollowRedirects(true);
        
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) page.openConnection();
        } catch (IOException e) {}
        textField.setText("");

        TextDocument document = new TextDocument("untitled" + docCount, newWindowX, newWindowY);
        this.addDocument(document);
        docCount++;
        document.textArea.append(page.getHost());
        try {
            document.textArea.read(new InputStreamReader(conn.getInputStream()), null);
        } catch (IOException e) {}
     }

	/**
	 * Adds a document to the desktop pane
	 * 
	 * @param document
	 *				The Document to be added to the
	 *				desktop pane
	 */
	private void addDocument(Document document) {
		pane.add(document);
		pane.getDesktopManager().activateFrame(document);
		try {
			document.setSelected(true);
		} catch (Exception ex) {
			ex.printStackTrace();
        }
        
		// The following line takes the task bar into acount
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		screenSize.height = screenSize.height - (25 * screenSize.height / 768); 
		// Compute co-ords for posn of next new window
		newWindowX = (newWindowX + 20) % (int) (screenSize.width - 100);
		newWindowY = (newWindowY + 20) % (int) (screenSize.height - 100);
		document.grabFocus();
	}

	/**
	 * Accesses the currently selected document
	 * 
	 * @return
	 *			The TextDocument object of the
				currently selected document.
	 */
	private TextDocument getSelectedDocument() {
		JInternalFrame[] frames = pane.getAllFrames();
		for (int i = 0; i < frames.length; i++) {
			if (frames[i].isSelected())
				return (TextDocument) frames[i];
		}
		return null;
    }
}