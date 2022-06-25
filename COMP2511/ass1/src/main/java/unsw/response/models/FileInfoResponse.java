package unsw.response.models;

import java.util.Objects;

/**
 * Represents a file that is currently being transferred
 * or has been transferred to a device.
 * 
 * @note You can't store this class in BlackoutController and should just create
 *       it when needed, using this will make you lose marks for design
 *       modelling. (it's an okay start, but there is much more work to be
 *       done).
 * 
 *       You shouldn't modify this file.
 * 
 * @author Braedon Wooding
 */
public final class FileInfoResponse {
    /**
     * The filename for the file.
     */
    private final String filename;

    /**
     * The currently transferred data for the file.
     */
    private final String data;

    /**
     * The final size for the file.
     */
    private final int fileSize;

    /**
     * Has transfer for this file been completed yet?
     */
    private final boolean hasTransferCompleted;
    
    public FileInfoResponse(String filename, String data, int fileSize, boolean hasTransferCompleted) {
        this.filename = filename;
        this.data = data;
        this.fileSize = fileSize;
        this.hasTransferCompleted = hasTransferCompleted;
    }

    public final boolean hasTransferCompleted() {
        return hasTransferCompleted;
    }

    public final int getFileSize() {
        return fileSize;
    }

    public final String getData() {
        return data;
    }

    public final String getFilename() {
        return filename;
    }

    @Override
    public String toString() {
        return "FileInfoResponse [data=" + data + ", fileSize=" + fileSize + ", filename=" + filename
                + ", hasTransferCompleted=" + hasTransferCompleted + "]";
    }

    @Override
    public int hashCode() {
        return Objects.hash(data, fileSize, filename, hasTransferCompleted);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;

        FileInfoResponse other = (FileInfoResponse) obj;
        return Objects.equals(data, other.data) && fileSize == other.fileSize
                && Objects.equals(filename, other.filename) && hasTransferCompleted == other.hasTransferCompleted;
    }
}
