package unsw.blackout.interfaces;

import java.util.Map;

import unsw.blackout.File;
import unsw.response.models.FileInfoResponse;

public interface FileInteractable {
    boolean checkFileCapacity(int size);
    void addFile(String filename, String content, int fileSize, boolean hasTransferCompleted);
    void deleteFile(String filename);
    Map<String, File> getFiles();
    Map<String, FileInfoResponse> getFilesInfo();

}