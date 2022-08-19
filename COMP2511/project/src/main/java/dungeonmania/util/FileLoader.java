package dungeonmania.util;

import org.reflections.Reflections;
import org.reflections.scanners.Scanners;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public final class FileLoader {
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
        return new String(FileLoader.class.getResourceAsStream(path).readAllBytes());
    }

    /**
     * Lists file names (without extension) within a specified resource directory.
     * 
     * @param directory The directory relative to `resources` to look for files.
     *                  Will add a `/` prefix if it doesn't exist.
     *                  Typically is something like `/dungeons`
     * 
     * @return A list of *only* filenames with no extensions nor relative/absolute
     *         paths i.e. [maze, otherFile]
     * 
     */
    public static List<String> listFileNamesInResourceDirectory(String directory) {
        Reflections reflections = new Reflections(directory, Scanners.Resources);
        return reflections.getResources(".*\\.json")
                .stream()
                .map(s -> s.replace(directory + "/", "").replace(".json", ""))
                .collect(Collectors.toList());
    }
}
