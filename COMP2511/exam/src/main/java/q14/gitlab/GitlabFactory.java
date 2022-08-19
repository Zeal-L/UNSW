package q14.gitlab;

import java.io.IOException;

public class GitlabFactory {
    /**
     * Loads a resource file given a certain path that is relative to resources/
     * for example `/dungeons/maze.json`. Will add a `/` prefix to path if it's not
     * specified.
     * 
     * @precondiction path exists as a file
     * @param path Relative to resources/ will add an implicit `/` prefix if not
     *             given.
     * @return The textual content of the given file.
     * @throws IOException If some other IO exception.
     */
    public static String loadResourceFile(String path) throws IOException {
        if (!path.startsWith("/"))
            path = "/" + path;
        return new String(GitlabFactory.class.getResourceAsStream(path).readAllBytes());
    }

    public static GitlabPermissionsNode gitlabFromJson(String jsonString, User owner) {
        return null;
    }
}