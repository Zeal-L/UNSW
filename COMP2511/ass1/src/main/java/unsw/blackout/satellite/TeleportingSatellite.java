package unsw.blackout.satellite;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import unsw.blackout.Entity;
import unsw.blackout.File;
import unsw.blackout.device.Device;
import unsw.utils.Angle;

public class TeleportingSatellite extends Satellite {

    // Moves at a linear velocity of 1,000 kilometres (1,000,000 metres) per minute
    private static final int SPEED = 1000;
    // Maximum range of 200,000 kilometres (200,000,000 metres)
    private static final int MAX_RANGE = 200000;
    // Can store up to 200 bytes and as many files as fits into that space.
    private static final int MAX_CAPACITY = 200;
    private boolean clockwise;

    public TeleportingSatellite(String id, String type, double height, Angle position) {
        super(id, type, height, position, 10, 15);
        clockwise = false;
    }

    public int getSpeed() { return SPEED; }

    public int getMaxRange() { return MAX_RANGE; }

    public boolean checkFileCapacity(int size) {
        int count = 0;
        for (File file : getFiles().values()) {
            count += file.getFileSize();
        }
        if (count + size > MAX_CAPACITY) return false;
        return true;
    }

    public void deleteTafterTeleport(ArrayList<Device> devices, ArrayList<Satellite> satellites) {
        for (Satellite satellite : satellites) {
            
            if (satellite.getSendProgress().get(this) == null) continue;
            for (Iterator<Entity> receiverIterator = satellite.getSendProgress().keySet().iterator(); receiverIterator.hasNext();) {
                Entity receiver = receiverIterator.next();
                List<Map<String, Queue<Character>>> allFiles = satellite.getSendProgress().get(this);
                if (allFiles == null) continue;
                for (Iterator<Map<String, Queue<Character>>> fileIterator = allFiles.iterator(); fileIterator.hasNext();) {
                    Map<String, Queue<Character>> fileInfo = fileIterator.next();
        
                    String fileName = fileInfo.keySet().iterator().next();
                    Queue<Character> data = fileInfo.get(fileName);
        
                    while (!data.isEmpty()) {
                        Character c = data.poll();
                        if (c != 't') receiver.receiveFile(fileName, c);
                    }
                    File file = File.searchFileById(getFiles(), fileName);
                    file.setTransferCompleted(true);
                    file.setFileSize(file.getData().length());
                    
                }
                receiverIterator.remove();
            }
        }
        for (Device device : devices) {
            List<Map<String, Queue<Character>>> temp = device.getSendProgress().get(this);
            if (temp != null) {
                // get all the file name then delete them from device
                for (Iterator<Map<String, Queue<Character>>> file = temp.iterator(); file.hasNext();) {
                    String fileName = file.next().keySet().iterator().next();
                    File.searchFileById(device.getFiles(), fileName).deleteAllT();
                    getFiles().remove(fileName);
                }
                temp.clear();
            }
        }
        for (Iterator<Entity> receiverIterator = getSendProgress().keySet().iterator(); receiverIterator.hasNext();) {
            Entity receiver = receiverIterator.next();
            List<Map<String, Queue<Character>>> allFiles = getSendProgress().get(receiver);
            for (Iterator<Map<String, Queue<Character>>> fileIterator = allFiles.iterator(); fileIterator.hasNext();) {
                Map<String, Queue<Character>> fileInfo = fileIterator.next();
    
                String fileName = fileInfo.keySet().iterator().next();
                Queue<Character> data = fileInfo.get(fileName);
    
                while (!data.isEmpty()) {
                    Character c = data.poll();
                    if (c != 't') receiver.receiveFile(fileName, c);
                }
                File file = File.searchFileById(receiver.getFiles(), fileName);
                file.setTransferCompleted(true);
                file.setFileSize(file.getData().length());
                
            }
            receiverIterator.remove();
        }
        
    }

    @Override
    public void simulate(ArrayList<Device> devices, ArrayList<Satellite> satellites) {
        // When the position of the satellite reaches θ = 180, 
        // the satellite teleports to θ = 0 and changes direction.
        if (clockwise) {
            if (getPosition().toDegrees() > 180 && getPosition().subtract(Angle.fromRadians(SPEED / getHeight())).toDegrees() <= 180) {
                setPosition(Angle.fromRadians(Math.PI * 2));
                deleteTafterTeleport(devices, satellites);
                clockwise = false;
            } else {
                setPosition(getPosition().subtract(Angle.fromRadians(SPEED / getHeight())));
                
            }
            if (getPosition().toDegrees() < 0) {
                setPosition(Angle.fromRadians(getPosition().toRadians() + Math.PI * 2));
            }
            
        } else {
            if (getPosition().toDegrees() < 180 && getPosition().add(Angle.fromRadians(SPEED / getHeight())).toDegrees() >= 180) {
                setPosition(Angle.fromRadians(Math.PI * 2));
                deleteTafterTeleport(devices, satellites);
                clockwise = true;
            } else {
                setPosition(getPosition().add(Angle.fromRadians(SPEED / getHeight())));
                
            }

            if (getPosition().toDegrees() > 360) {
                setPosition(Angle.fromRadians(getPosition().toRadians() - Math.PI * 2));
            }
        }
        super.simulate(devices, satellites);
    }
}
