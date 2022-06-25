package unsw.blackout;

/**
 * Represents an exception that occured because of a file transfer.
 */
public class FileTransferException extends Exception {
    public FileTransferException(String message) {
        super(message);
    }

    /**
     * Represents the case where the targeted file wasn't found on the source.
     */
    public static class VirtualFileNotFoundException extends FileTransferException {
        public VirtualFileNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * Represents the case where the targeted file already existed on the target
     * or was in the process of downloading.
     */
    public static class VirtualFileAlreadyExistsException extends FileTransferException {
        public VirtualFileAlreadyExistsException(String message) {
            super(message);
        }
    }

    /**
     * Represents the case when no more bandwidth exists for a satellite to
     * be able to use for new devices.
     */
    public static class VirtualFileNoBandwidthException extends FileTransferException {
        public VirtualFileNoBandwidthException(String message) {
            super(message);
        }
    }

    /**
     * Occurs when a satellite runs out of space.
     */
    public static class VirtualFileNoStorageSpaceException extends FileTransferException {
        public VirtualFileNoStorageSpaceException(String message) {
            super(message);
        }
    }
}
