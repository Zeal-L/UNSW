package unsw.blackout;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import unsw.blackout.FileTransferException.VirtualFileAlreadyExistsException;
import unsw.blackout.FileTransferException.VirtualFileNoBandwidthException;
import unsw.blackout.FileTransferException.VirtualFileNoStorageSpaceException;
import unsw.blackout.FileTransferException.VirtualFileNotFoundException;
import unsw.blackout.device.Device;
import unsw.blackout.interfaces.*;
import unsw.blackout.satellite.Satellite;
import unsw.response.models.FileInfoResponse;
import unsw.utils.Angle;

public abstract class Entity implements Movable, FileInteractable, FileTransferable {
    private String id;
    private String type;
    private Angle position;
    private double height;
    private Map<String, File> files;
    private Map<String, Integer> downloadFromNum;
    /**
     * receiverId -> List<fileName -> data>
     */
    private Map<Entity, List<Map<String, Queue<Character>>>> sendProgress;

    public Entity(String id, String type, double height, Angle position) {
        this.id = id;
        this.type = type;
        this.height = height;
        this.position = position;
        this.files = new HashMap<>();
        this.sendProgress = new HashMap<>();
        this.downloadFromNum = new HashMap<>();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Angle getPosition() {
        return position;
    }

    public void setPosition(Angle position) {
        this.position = position;
    }

    public double getHeight() {
        return height;
    }

    public void setHeight(double height) {
        this.height = height;
    }

    public Map<Entity, List<Map<String, Queue<Character>>>> getSendProgress() {
        return sendProgress;
    }

    public int getUploadNumber() {
        return sendProgress.size();
    }

    public void updateDownloadFromNum(String id) {
        if (downloadFromNum.containsKey(id)) {
            downloadFromNum.put(id, downloadFromNum.get(id) + 1);
        } else {
            downloadFromNum.put(id, 1);
        }
    }

    public int getDownloadFromNum(String id) {
        int totalNumberOfFiles = 0;
        for (int n : downloadFromNum.values()) {
            totalNumberOfFiles += n;
        }
        int limit = getDownloadSpeed() / (totalNumberOfFiles == 0 ? 1 : totalNumberOfFiles);
        return limit * downloadFromNum.get(id);
    }

    public int getDownloadNumber() {
        int count = 0;
        for (File file : files.values()) {
            if (file.getHasTransferCompleted() == false) {
                count++;
            }
        }
        return count;
    }

    public void addFile(String filename, String content, int fileSize, boolean hasTransferCompleted) {
        files.put(filename, new File(filename, content, fileSize, hasTransferCompleted));
    }

    public void deleteFile(String filename) {
        files.remove(filename);
    }

    public Map<String, File> getFiles() {
        return files;
    }

    public Map<String, FileInfoResponse> getFilesInfo() {
        Map<String, FileInfoResponse> tempInfo = new HashMap<>();
        for (Map.Entry<String, File> file : files.entrySet()) {
            File temp = file.getValue();
            tempInfo.put(file.getKey(), new FileInfoResponse(temp.getFilename(), temp.getData(), temp.getFileSize(), temp.getHasTransferCompleted()));
        }
        return tempInfo;
    }

    abstract public void simulate(ArrayList<Device> devices, ArrayList<Satellite> satellites);
    abstract public void communicableEntitiesInRange(List<String> communicable, ArrayList<Device> devices, ArrayList<Satellite> satellites);

    public void sendFile(String fileName, Entity receiver) throws FileTransferException {
        Map<String, Queue<Character>> fileInfo = new HashMap<>();
        Queue<Character> fullData = new LinkedList<Character>();
        File myFile = File.searchFileById(this.files, fileName);
        File receiverFile = File.searchFileById(receiver.getFiles(), fileName);
        
        if (myFile == null || myFile.getHasTransferCompleted() == false) 
            throw new VirtualFileNotFoundException(fileName);
        if (receiverFile != null) 
            throw new VirtualFileAlreadyExistsException(fileName);
        if (receiver.getDownloadNumber() >= receiver.getDownloadSpeed())
            throw new VirtualFileNoBandwidthException(receiver.getId());
        if (!receiver.checkFileCapacity(myFile.getFileSize()))
            throw new VirtualFileNoStorageSpaceException("Max Files Reached");

        char[] chars = myFile.getData().toCharArray();
        for (char c : chars) {
            fullData.add(c);
        }
        fileInfo.put(fileName, fullData);
        if (sendProgress.get(receiver) == null) {
            List<Map<String, Queue<Character>>> allFiles = new LinkedList<Map<String, Queue<Character>>>();
            allFiles.add(fileInfo);
            sendProgress.put(receiver, allFiles);
        } else {
            sendProgress.get(receiver).add(fileInfo);
        }

        receiver.addFile(fileName, "", myFile.getFileSize(), false);
        receiver.updateDownloadFromNum(getId());
    }
    public void receiveFile(String fileName, Character c) {
        File file = File.searchFileById(this.files, fileName);
        file.appendDate(c);
    }

}
