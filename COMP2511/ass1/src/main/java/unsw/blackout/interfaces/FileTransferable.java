package unsw.blackout.interfaces;

import java.util.List;
import java.util.Map;
import java.util.Queue;

import unsw.blackout.Entity;
import unsw.blackout.FileTransferException;

public interface FileTransferable {
    Map<Entity, List<Map<String, Queue<Character>>>> getSendProgress();
    int getUploadNumber();
    int getDownloadNumber();
    int getDownloadSpeed();
    int getDownloadFromNum(String id);
    void updateDownloadFromNum(String id);
    void sendFile(String fileName, Entity receiver) throws FileTransferException;
    void receiveFile(String fileName, Character c);
    int getMaxRange();
}
