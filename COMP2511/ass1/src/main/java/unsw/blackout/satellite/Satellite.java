package unsw.blackout.satellite;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import unsw.blackout.Entity;
import unsw.blackout.File;
import unsw.blackout.FileTransferException;
import unsw.blackout.FileTransferException.VirtualFileNoBandwidthException;
import unsw.blackout.device.Device;
import unsw.utils.Angle;
import unsw.utils.MathsHelper;

public abstract class Satellite extends Entity {

    private int uploadSpead;
    private int downloadSpeed;

    public Satellite(String id, String type, double height, Angle position, int uploadSpead, int downloadSpeed) {
        super(id, type, height, position);
        this.uploadSpead = uploadSpead;
        this.downloadSpeed = downloadSpeed;
    }

    public int getUploadSpeed() { return uploadSpead; }
    public int getDownloadSpeed() { return downloadSpeed; }

    public void simulate(ArrayList<Device> devices, ArrayList<Satellite> satellites) {
        if (getSendProgress().size() == 0) return;
        int bandwidth = getUploadSpeed();
        
        for (int i = 0; i < bandwidth;) {
            if (getSendProgress().values().size() == 0) break;
            for (Entity receiver : getSendProgress().keySet()) {
                List<String> communicable = new ArrayList<String>();
                communicableEntitiesInRange(communicable, devices, satellites);
                if (!communicable.contains(receiver.getId())) {
                    for (Map<String, Queue<Character>> fileInfo : getSendProgress().get(receiver)) {
                        receiver.deleteFile(fileInfo.keySet().iterator().next());
                        getSendProgress().remove(receiver);
                    }
                    continue;
                }
                
                int receiverBandwidth = receiver.getDownloadFromNum(getId());
                bandwidth = Integer.min(bandwidth, receiverBandwidth);
                List<Map<String, Queue<Character>>> allFiles = getSendProgress().get(receiver);
                for (Iterator<Map<String, Queue<Character>>> fileIterator = allFiles.iterator(); fileIterator.hasNext();) {
                    Map<String, Queue<Character>> fileInfo = fileIterator.next();
                    // Satellites will always ensure fairness and will evenly 
                    // allocate bandwidth to all currently uploading files
                    bandwidth = bandwidth - (bandwidth % allFiles.size());
                    String fileName = fileInfo.keySet().iterator().next();
                    if (i++ > bandwidth) break;
                    Queue<Character> data = fileInfo.get(fileName);
                    receiver.receiveFile(fileName, data.poll());

                    if (data.size() == 0) {
                        fileIterator.remove();
                        File file = File.searchFileById(receiver.getFiles(), fileName);
                        file.setTransferCompleted(true);
                        break;
                    }
                    if (allFiles.size() == 0) getSendProgress().remove(receiver);
                }
            }
        }
    }
    public void communicableEntitiesInRange(List<String> communicable, ArrayList<Device> devices, ArrayList<Satellite> satellites) {

        for (Device device : devices) {
            if (getType().equals("StandardSatellite")) {
                String toCompare = device.getType();
                if (!(toCompare.equals("HandheldDevice") || toCompare.equals("LaptopDevice"))) {
                    continue;
                }
            }
            if (!MathsHelper.isVisible(getHeight(), getPosition(), device.getPosition())) {
                continue;
            }
            if (MathsHelper.getDistance(device.getHeight(), device.getPosition(), getPosition()) > getMaxRange()) {
                continue;
            }
            if (!communicable.contains(device.getId())) communicable.add(device.getId());
        }

        for (Satellite satellite : satellites) {
            if (satellite.getId().equals(getId())) {
                continue;
            }
            if (!MathsHelper.isVisible(getHeight(), getPosition(), 
                            satellite.getHeight(), satellite.getPosition())) {
                continue;
            }
            if (MathsHelper.getDistance(satellite.getHeight(), satellite.getPosition(), getPosition()) > getMaxRange()) {
                continue;
            }
            if (!communicable.contains(satellite.getId()) && satellite.getType().equals("RelaySatellite")) {
                communicable.add(satellite.getId());
                satellite.communicableEntitiesInRange(communicable, devices, satellites);
            }
            if (!communicable.contains(satellite.getId())) {
                communicable.add(satellite.getId());
            }
        }
    }
    
    @Override
    public void sendFile(String fileName, Entity receiver) throws FileTransferException {
        if (getUploadNumber() >= getUploadSpeed())
            throw new VirtualFileNoBandwidthException(getId());
        super.sendFile(fileName, receiver);
    }

}
