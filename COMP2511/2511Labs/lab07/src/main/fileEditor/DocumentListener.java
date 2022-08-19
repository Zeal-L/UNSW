package fileEditor;

import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;

/**
 * Listens to closing of document and 
 * prompts save of individual document
 */
public class DocumentListener extends InternalFrameAdapter {

	/**
	 * Creates a new DocumentListener object attached
	 * to the given Document object 
	 *
	 * @param doc
	 *				the Document object to be listened to
	 */
	public DocumentListener(Document doc) {
		this.document = doc;
	}

	/**
	 * Saves the document being listened to if the internal
	 * frame is closed.
	 * 
	 * @param event
	 *				the InternalFrameEvent object indicating that
					the frame is being closed.
	 */
	public void internalFrameClosing(InternalFrameEvent event) {
		document.saveAs();
	}

	private Document document;
}