package fileEditor;

import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;

import javax.swing.JDesktopPane;
import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JToolBar;

import java.awt.Dimension;
import java.awt.Toolkit;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDesktopPane;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JTextField;
import javax.swing.JToolBar;

public class EditorApplication {

    private JFrame frame;
    private JMenuBar menuBar;
    private JToolBar toolBar;
    private WindowAdapter windowAdapter;
    private JDesktopPane pane;
    private ActionListener listener;

    public EditorApplication(String type) {

        if (type.equals("HTML Editor")) {
            // Create Frame
            this.frame = new JFrame("Basic Editor");
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            screenSize.height = screenSize.height - (25 * screenSize.height / 768);
            frame.setSize(screenSize);

            // Create Desktop Pane
            this.pane = new JDesktopPane();

            // Create Action Listener
            this.listener = new ButtonListener(pane);

            // Create Menu Bar
            this.menuBar = new JMenuBar();
            JMenu fileMenu = new JMenu("File");
            String[] fileMenuItems = new String[] { "New", "Open", "Save", "Save As" };
            for (int i = 0; i < fileMenuItems.length; i++) {
                JMenuItem menuItem = new JMenuItem(fileMenuItems[i]);
                fileMenu.add(menuItem);
                menuItem.addActionListener(listener); // Listens to button press
            }
            menuBar.add(fileMenu);

            //      Edit menu
            JMenu editMenu = new JMenu("Edit");
            String[] editMenuItems = new String[] { "Copy", "Cut", "Paste", "Select All" };

            for (int i = 0; i < editMenuItems.length; i++) {
                JMenuItem menuItem = new JMenuItem(editMenuItems[i]);
                editMenu.add(menuItem);
                menuItem.addActionListener(listener); // Listens to button press
            }
            menuBar.add(editMenu);

            JTextField urlField = new JTextField();
            JButton goUrl = new JButton("Go");
            ButtonListener blistener = (ButtonListener) listener;
            blistener.setTextField(urlField);

            goUrl.addActionListener(listener);
            menuBar.add(urlField);
            menuBar.add(goUrl);

            // Create Tool Bar
            this.toolBar = new JToolBar();
            String[] buttons = new String[] { "New", "Open", "Save", "Copy", "Cut", "Paste" };

            for (int i = 0; i < buttons.length; i++) {
                JButton button = new JButton(buttons[i], new ImageIcon(buttons[i] + ".jpg"));
                button.setPreferredSize(new Dimension(500, 50));
                toolBar.add(button);
                button.addActionListener(listener);
                if (i == 2)
                    toolBar.addSeparator(new Dimension(10, toolBar.getHeight()));
            }

            // Create Window Adapter
            this.windowAdapter = new WindowCloser(pane);

            // Add Components to Frame
            frame.setJMenuBar(menuBar);
            frame.addWindowListener(windowAdapter);
            frame.getContentPane().add(toolBar, "North");
            frame.getContentPane().add(pane);

        } else if (type.equals("Text Editor")) {

            // Create Frame
            this.frame = new JFrame("Basic Editor");
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            screenSize.height = screenSize.height - (25 * screenSize.height / 768);
            frame.setSize(screenSize);

            // Create Desktop Pane
            this.pane = new JDesktopPane();

            // Create Action Listener
            this.listener = new ButtonListener(pane);

            // Create Menu Bar
            JMenuBar menuBar = new JMenuBar();
            JMenu fileMenu = new JMenu("File");
            String[] fileMenuItems = new String[] { "New", "Open", "Save", "Save As" };

            for (int i = 0; i < fileMenuItems.length; i++) {
                JMenuItem menuItem = new JMenuItem(fileMenuItems[i]);
                fileMenu.add(menuItem);
                menuItem.addActionListener(listener); // Listens to button press
            }
            menuBar.add(fileMenu);

            //      Edit menu
            JMenu editMenu = new JMenu("Edit");
            String[] editMenuItems = new String[] { "Copy", "Cut", "Paste", "Select All" };

            for (int i = 0; i < editMenuItems.length; i++) {
                JMenuItem menuItem = new JMenuItem(editMenuItems[i]);
                editMenu.add(menuItem);
                menuItem.addActionListener(listener); // Listens to button press
            }
            menuBar.add(editMenu);

            // Create tool bar
            this.toolBar = new JToolBar();
            String[] buttons = new String[] { "New", "Open", "Save", "Copy", "Cut", "Paste" };

            for (int i = 0; i < buttons.length; i++) {
                JButton button = new JButton(buttons[i], new ImageIcon(buttons[i] + ".jpg"));
                button.setPreferredSize(new Dimension(500, 50));
                toolBar.add(button);
                button.addActionListener(listener);
                if (i == 2)
                    toolBar.addSeparator(new Dimension(10, toolBar.getHeight()));
            }

            // Create Window Adapter
            this.windowAdapter = new WindowCloser(pane);

            // Add Components to Frame
            frame.setJMenuBar(menuBar);
            frame.addWindowListener(windowAdapter);
            frame.getContentPane().add(toolBar, "North");
            frame.getContentPane().add(pane);
        }
    }
    
    public void setFrameVisible(boolean value) {
        frame.setVisible(value);
    }

    public static void main(String[] args) {
        String editorType = "HTML Editor";
        EditorApplication editor = new EditorApplication(editorType);
        editor.setFrameVisible(true);
    }
	
}