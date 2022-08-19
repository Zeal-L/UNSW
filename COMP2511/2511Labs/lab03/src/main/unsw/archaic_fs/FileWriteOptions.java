package unsw.archaic_fs;

public enum FileWriteOptions {
    /** Force create file */
    CREATE,
    /** Create file if it doesn't exist */
    CREATE_IF_NOT_EXISTS,
    /** Append to file */
    APPEND,
    /** Truncate file */
    TRUNCATE,
}
