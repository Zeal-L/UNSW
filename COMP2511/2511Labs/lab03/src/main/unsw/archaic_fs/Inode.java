package unsw.archaic_fs;

public class Inode {
    private int inode;
    private Metadata metadata;
    private String name;
    private int parentInode;

    private Inode(int inode, Metadata metadata, String name, int parentInode) {
        this.inode = inode;
        this.metadata = metadata;
        this.name = name;
        this.parentInode = parentInode;
    }

    public int getInode() {
        return inode;
    }

    public Metadata stat() {
        return metadata;
    }

    public String filename() {
        return name;
    }

    public int getParentInode() {
        return parentInode;
    }

    public static Inode createFile(String name, int inode, int parentInode) {
        return new Inode(inode, new Metadata(DeviceType.FILE), name, parentInode);
    }

    public static Inode createFolder(String name, int inode, int parentInode) {
        return new Inode(inode, new Metadata(DeviceType.FOLDER), name, parentInode);
    }
}
