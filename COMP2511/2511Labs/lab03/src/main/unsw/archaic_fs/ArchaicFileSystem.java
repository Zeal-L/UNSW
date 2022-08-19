package unsw.archaic_fs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import unsw.archaic_fs.exceptions.UNSWFileAlreadyExistsException;
import unsw.archaic_fs.exceptions.UNSWFileNotFoundException;
import unsw.archaic_fs.exceptions.UNSWNoSuchFileException;

/**
 * Represents an 'archaic' file system. This allows you to 'open' files, 'make'
 * directories, 'write' to a file, and so on.
 * 
 * Operates 'entirely' virtually, with no actual file write operations performed
 * 
 * Doesn't support ~ but does support `..`
 */
public class ArchaicFileSystem {
    private List<Inode> inodeLookup = new ArrayList<Inode>();
    private List<Inode> currentPath = new ArrayList<Inode>();

    // Note... this is an indication of bad design here!
    // next week we'll see how we can design this to be much better.
    private Map<Integer, List<Integer>> folderMap = new HashMap<>();
    private Map<Integer, String> fileContent = new HashMap<>();

    public ArchaicFileSystem() {
        // create base folders
        // i.e. /usr/
        // / root directory
        currentPath.add(_mkdir(-1, ""));
        try {
            mkdir("/usr/", false, false);
        } catch (IOException e) {
            // presuming that we can't fail this creation!
        }
    }

    public Inode lookupInode(int inode) {
        if (inode >= 0 && inode < inodeLookup.size()) {
            return inodeLookup.get(inode);
        } else {
            return null;
        }
    }

    private Inode _mkfile(int parent, String filename) {
        int inode = inodeLookup.size();
        Inode file = Inode.createFile(filename, inode, parent);
        inodeLookup.add(file);
        folderMap.get(parent).add(inode);
        fileContent.put(inode, "");
        return file;
    }

    private Inode _mkdir(int parent, String dirName) {
        int inode = inodeLookup.size();
        Inode dir = Inode.createFolder(dirName, inode, parent);
        folderMap.put(inode, new ArrayList<>());
        inodeLookup.add(dir);
        return dir;
    }

    private String formPathForInode(Inode inode) {
        if (inode.getParentInode() == -1) {
            return inode.filename();
        } else {
            return formPathForInode(lookupInode(inode.getParentInode())) + "/" + inode.filename();
        }
    }

    public void reformPathForInode(Inode inode, int stop) {
        if (inode.getParentInode() == stop) {
            return;
        } else {
            reformPathForInode(lookupInode(inode.getParentInode()), stop);
            currentPath.add(inode);
        }
    }

    private Inode lookupInodeInDirInode(String path, Inode inode, DeviceType wantedType) throws IOException {
        if (inode.stat().getType() != DeviceType.FOLDER) {
            throw new IOException(formPathForInode(inode) + " is a file not a folder");
        }

        if (path.equals("..") && wantedType.equals(DeviceType.FOLDER)) {
            return inodeLookup.get(Math.max(inode.getParentInode(), 0));
        }

        List<Integer> subInodes = folderMap.get(inode.getInode());

        for (Integer subInode : subInodes) {
            Inode i = inodeLookup.get(subInode);
            if (i.filename().equals(path) && i.stat().getType().equals(wantedType)) {
                // move to next component
                return inodeLookup.get(subInode);
            }
        }

        return null;
    }

    private Inode topPathComponent() {
        return currentPath.get(currentPath.size() - 1);
    }

    public void mkdir(String path, boolean createParentDirectories, boolean ignoreIfExists) throws IOException {
        // not really fast at all, but simple...
        Inode current = topPathComponent();

        if (path.startsWith("/")) {
            path = path.substring(1);
            current = currentPath.get(0);
        }

        String[] pathComponents = path.split("/");

        for (int i = 0; i < pathComponents.length; i++) {
            Inode inode = lookupInodeInDirInode(pathComponents[i], current, DeviceType.FOLDER);
            if (inode == null) {
                if (createParentDirectories || i == pathComponents.length - 1) {
                    current = _mkdir(current.getInode(), pathComponents[i]);
                    folderMap.get(current.getParentInode()).add(current.getInode());
                } else {
                    throw new UNSWFileNotFoundException(formPathForInode(current) + "/" + pathComponents[i]);
                }
            } else if (ignoreIfExists || i != pathComponents.length - 1) {
                current = inode;
            } else {
                throw new UNSWFileAlreadyExistsException(formPathForInode(current) + "/" + pathComponents[i]);
            }
        }
    }

    public String cwd() {
        return currentPath.stream().<String>map(i -> i.filename()).collect(Collectors.joining("/"));
    }

    public void cd(String path) throws IOException {
        Inode current = topPathComponent();

        // go to root
        if (path.startsWith("/")) {
            path = path.substring(1);
            current = currentPath.get(0);
        }

        String[] pathComponents = path.split("/");
        for (String component : pathComponents) {
            Inode inode = lookupInodeInDirInode(component, current, DeviceType.FOLDER);
            if (inode == null) {
                throw new UNSWNoSuchFileException(formPathForInode(current) + "/" + component);
            } else {
                current = inode;
            }
        }

        currentPath.clear();
        currentPath.add(inodeLookup.get(0));
        reformPathForInode(current, -1);
    }

    private Inode searchForInodeFileParent(String path) throws IOException {
        // first we need to 'cd' into that path.
        Inode current = topPathComponent();

        if (path.startsWith("/")) {
            path = path.substring(1);
            current = currentPath.get(0);
        }

        String[] pathComponents = path.split("/");

        for (int i = 0; i < pathComponents.length - 1; i++) {
            Inode inode = lookupInodeInDirInode(pathComponents[i], current, DeviceType.FOLDER);
            if (inode == null) {
                throw new UNSWFileNotFoundException(formPathForInode(current) + "/" + pathComponents[i]);
            } else {
                current = inode;
            }
        }

        return current;
    }

    public String readFromFile(String path) throws IOException {
        Inode current = searchForInodeFileParent(path);
        String filename = path.substring(path.lastIndexOf('/') + 1);
        Inode inode = lookupInodeInDirInode(filename, current, DeviceType.FILE);

        if (inode != null) {
            return fileContent.get(inode.getInode());
        } else {
            // doesn't exist
            throw new UNSWFileNotFoundException(formPathForInode(current) + "/" + filename);
        }
    }

    public void writeToFile(String path, String content, EnumSet<FileWriteOptions> opts) throws IOException {
        if (opts.contains(FileWriteOptions.TRUNCATE) && opts.contains(FileWriteOptions.APPEND)) {
            throw new IllegalArgumentException("Can't have both Truncate & Append enabled");
        }
        if (!opts.contains(FileWriteOptions.TRUNCATE) && !opts.contains(FileWriteOptions.APPEND)) {
            throw new IllegalArgumentException("Has to have either Truncate or Append enabled");
        }

        Inode current = searchForInodeFileParent(path);
        String filename = path.substring(path.lastIndexOf('/') + 1);
        Inode inode = lookupInodeInDirInode(filename, current, DeviceType.FILE);

        if (opts.contains(FileWriteOptions.CREATE)) {
            if (inode == null) {
                inode = _mkfile(current.getInode(), filename);
            } else {
                throw new UNSWFileAlreadyExistsException(formPathForInode(current) + "/" + filename);
            }
        } else if (inode == null && opts.contains(FileWriteOptions.CREATE_IF_NOT_EXISTS)) {
            inode = _mkfile(current.getInode(), filename);
        } else if (inode == null) {
            // doesn't exist
            throw new UNSWFileNotFoundException(formPathForInode(current) + "/" + filename);
        }

        // now to write to it
        if (opts.contains(FileWriteOptions.TRUNCATE)) {
            fileContent.put(inode.getInode(), content);
        } else if (opts.contains(FileWriteOptions.APPEND)) {
            fileContent.put(inode.getInode(), fileContent.get(inode.getInode()) + content);
        } // unreachable else
    }
}
