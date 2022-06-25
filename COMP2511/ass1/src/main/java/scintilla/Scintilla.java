package scintilla;

public class Scintilla {
    // block initialisation of multiple WebServers
    private Scintilla() {}
    private static final WebServer INSTANCE = new WebServer();

    public static void initialize() {
        INSTANCE.initialize();
    }

    public static void start() {
        INSTANCE.finalize();
        PlatformUtils.openBrowserAtPath(INSTANCE.getHostUrl() + "/app/");
    }
}
