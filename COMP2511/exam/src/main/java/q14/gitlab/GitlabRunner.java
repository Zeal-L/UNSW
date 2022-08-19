package q14.gitlab;

public final class GitlabRunner {
    
    private static volatile GitlabRunner instance;
    public static GitlabRunner getInstance() {
        GitlabRunner result = instance;
        if (result != null) {
            return result;
        }
        synchronized(GitlabRunner.class) {
            if (instance == null) {
                instance = new GitlabRunner();
            }
            return instance;
        }
    }

    private GitlabRunner() {
    }

    public synchronized void run(Runnable runnable) {
        try {
            runnable.run();
        } catch (Throwable t) {}
    }
}