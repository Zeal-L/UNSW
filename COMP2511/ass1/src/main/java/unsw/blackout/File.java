package unsw.blackout;

import java.util.Map;

public final class File {
    private final String filename;
    private String data;
    private int fileSize;
    private boolean hasTransferCompleted;
    
    public File(String filename, String data, int fileSize, boolean hasTransferCompleted) {
        this.filename = filename;
        this.data = data;
        this.fileSize = fileSize;
        this.hasTransferCompleted = hasTransferCompleted;
    }

    public final boolean getHasTransferCompleted() {
        return hasTransferCompleted;
    }

    public final void setTransferCompleted(boolean hasTransferCompleted) {
        this.hasTransferCompleted = hasTransferCompleted;
    }

    public final int getFileSize() {
        return fileSize;
    }

    public final void setFileSize(int fileSize) {
        this.fileSize = fileSize;
    }

    public final String getData() {
        return data;
    }

    public final void deleteAllT() {
        // remove all "t" from data
        data = data.replaceAll("t", "");
        fileSize = data.length();
    }

    public final String getFilename() {
        return filename;
    }

    public final void appendDate(Character c) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(data);
        stringBuilder.append(c);
        data = stringBuilder.toString();
    }

    public static File searchFileById(Map<String, File> files, String fileName) {
        return files.get(fileName);
    }
}
