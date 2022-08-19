package scintilla;

import java.io.IOException;
import java.util.Locale;

final class PlatformUtils {
    /**
     * Operating System's we support.
     */
    public static enum OperatingSystemType {
        Windows, MacOS, Linux, Unknown;
    };

    /**
     * Opens the user's specified browser at a given path
     * @param path The path (with protocol + host included) to open to.
     */
    public static final boolean openBrowserAtPath(String path) {
        // A way you could approach this is java.awt but that typically requires as many steps as this
        // and is pretty deprecated these days, this is just simpler and will be more crossplatform
        
        // Since students can call this directly we need to ensure we aren't running in headless
        if (Environment.isHeadless()) {
            System.err.println("Running in HEADLESS mode, denying Browser from opening.");
            return false;
        }

        String command;

        // Determine what command to run based on if we are Windows/Mac/Linux
        switch (determineOperatingSystem()) {
            case MacOS:
                command = "open";
                break;
            case Windows:
                command = "rundll32 url.dll,FileProtocolHandler";
                break;
            case Unknown: default: case Linux:
            //  if it's an unknown file system we'll just open it as linux since it's most likely something like Solaris
                command = "xdg-open";
                break;
        }

        try {
            // get a shell instance and execute the open browser command
            Runtime runtime = Runtime.getRuntime();
            runtime.exec(command + " " + path);
            return true;
        } catch (IOException e) {
            System.err.println("Failed to open browser (" + command + " " + path + ")");
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Determine what operating system the user has.
     * @return Either MacOs/Windows/Linux or Unknown if can't determine the OS.
     */
    public static final OperatingSystemType determineOperatingSystem() {
        String osName = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
        if (osName.contains("mac") || osName.contains("darwin")) {
            return OperatingSystemType.MacOS;
        } else if (osName.contains("win")) {
            return OperatingSystemType.Windows;
        } else if (osName.contains("nux") || osName.contains("nix") || osName.contains("aix")) {
            return OperatingSystemType.Linux;
        } else {
            System.err.println("Unknown/Unsupported Operating System... " + osName);
            return OperatingSystemType.Unknown;
        }
    }
}
