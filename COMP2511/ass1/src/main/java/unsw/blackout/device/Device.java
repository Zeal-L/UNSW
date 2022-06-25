package unsw.blackout.device;

import static unsw.utils.MathsHelper.RADIUS_OF_JUPITER;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import unsw.blackout.Entity;
import unsw.blackout.File;
import unsw.blackout.satellite.Satellite;
import unsw.utils.Angle;
import unsw.utils.MathsHelper;

public abstract class Device extends Entity {

    private boolean isMoving;
    
    public Device(String id, String type, Angle position, boolean isMoving) {
        super(id, type, RADIUS_OF_JUPITER, position);
        this.isMoving = isMoving;
    }

    public int getDownloadSpeed() { return Integer.MAX_VALUE; }

    public boolean checkFileCapacity(int size) { return true; }
    
    public void simulate(ArrayList<Device> devices, ArrayList<Satellite> satellites) { 
        if (isMoving) {
            setPosition(getPosition().add(Angle.fromRadians(getSpeed() / getHeight())));
            if (getPosition().toRadians() >= Math.PI * 2) {
                setPosition(Angle.fromRadians(getPosition().toRadians() - Math.PI * 2));
            }
        }

        for (Iterator<Entity> allReceiver = getSendProgress().keySet().iterator(); allReceiver.hasNext();) {
            Entity receiver = allReceiver.next();
            List<String> communicable = new ArrayList<String>();
            communicableEntitiesInRange(communicable, devices, satellites);
            if (!communicable.contains(receiver.getId())) {
                for (Map<String, Queue<Character>> fileInfo : getSendProgress().get(receiver)) {
                    receiver.deleteFile(fileInfo.keySet().iterator().next());
                    getSendProgress().remove(receiver);
                }
                continue;
            }

            List<Map<String, Queue<Character>>> allFiles = getSendProgress().get(receiver);
            for (int i = 0; i < receiver.getDownloadSpeed();) {
                if (!allFiles.iterator().hasNext()) break;
                for (Iterator<Map<String, Queue<Character>>> fileIterator = allFiles.iterator(); fileIterator.hasNext();) {
                    Map<String, Queue<Character>> fileInfo = fileIterator.next();
                    if (fileInfo.size() == 0) break;
                    String fileName = fileInfo.keySet().iterator().next();
                    if (i++ >= receiver.getDownloadSpeed()) break;
                    Queue<Character> data = fileInfo.get(fileName);
                    receiver.receiveFile(fileName, data.poll());

                    if (data.size() == 0) {
                        fileIterator.remove();
                        File file = File.searchFileById(receiver.getFiles(), fileName);
                        file.setTransferCompleted(true);
                        continue;
                    }
                }
            }
            if (!allFiles.iterator().hasNext()) allReceiver.remove();
        }
    }
    
    public void communicableEntitiesInRange(List<String> communicable, ArrayList<Device> devices, ArrayList<Satellite> satellites) {
        for (Satellite satellite : satellites) {
            if (!MathsHelper.isVisible(satellite.getHeight(), satellite.getPosition(), getPosition())) {
                continue;
            }
            if (MathsHelper.getDistance(satellite.getHeight(), satellite.getPosition(), getPosition()) > getMaxRange()) {
                continue;
            }
            if (!communicable.contains(satellite.getId()) && satellite.getType().equals("RelaySatellite")) {
                communicable.add(satellite.getId());
                satellite.communicableEntitiesInRange(communicable, devices, satellites);
            }
            if (!communicable.contains(satellite.getId())) communicable.add(satellite.getId());
        }
    }
}
