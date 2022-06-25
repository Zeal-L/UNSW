package unsw.blackout;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import unsw.blackout.device.DesktopDevice;
import unsw.blackout.device.Device;
import unsw.blackout.device.HandheldDevice;
import unsw.blackout.device.LaptopDevice;
import unsw.blackout.satellite.RelaySatellite;
import unsw.blackout.satellite.Satellite;
import unsw.blackout.satellite.StandardSatellite;
import unsw.blackout.satellite.TeleportingSatellite;
import unsw.response.models.EntityInfoResponse;
import unsw.utils.Angle;

public class BlackoutController {
    private ArrayList<Device> devices = new ArrayList<Device>();
    private ArrayList<Satellite> satellites = new ArrayList<Satellite>();
    
    private Comparator<Entity> compareById = (Entity u1, Entity u2) -> u1.getId().compareTo( u2.getId() );
    
    private void checkForDuplicatesId(String id) {
        for (Device d : devices) {
            if (d.getId().equals(id)) {
                throw new IllegalArgumentException("Duplicate id: " + id);
            }
        }
        for (Satellite s : satellites) {
            if (s.getId().equals(id)) {
                throw new IllegalArgumentException("Duplicate id: " + id);
            }
        }
    }

    public void createDevice(String deviceId, String type, Angle position) {
        checkForDuplicatesId(deviceId);
        if (type.equals("HandheldDevice")) {
            devices.add(new HandheldDevice(deviceId, type, position));
        } else if (type.equals("LaptopDevice")) {
            devices.add(new LaptopDevice(deviceId, type, position));
        } else if (type.equals("DesktopDevice")) {
            devices.add(new DesktopDevice(deviceId, type, position));
        }
        Collections.sort(devices, compareById);
    }

    public void removeDevice(String deviceId) {
        for (Device device : devices) {
            if (device.getId().equals(deviceId)) {
                devices.remove(device);
                break;
            }
        }
    }

    public void createSatellite(String satelliteId, String type, double height, Angle position) {
        checkForDuplicatesId(satelliteId);
        if (type.equals("StandardSatellite")) {
            satellites.add(new StandardSatellite(satelliteId, type, height, position));
        } else if (type.equals("TeleportingSatellite")) {
            satellites.add(new TeleportingSatellite(satelliteId, type, height, position));
        } else if (type.equals("RelaySatellite")) {
            satellites.add(new RelaySatellite(satelliteId, type, height, position));
        }
        Collections.sort(satellites, compareById);
    }

    public void removeSatellite(String satelliteId) {
        for (Satellite satellite : satellites) {
            if (satellite.getId().equals(satelliteId)) {
                satellites.remove(satellite);
                break;
            }
        }
    }

    public List<String> listDeviceIds() {
        List<String> deviceIds = new ArrayList<String>();
        for (Device device : devices) {
            deviceIds.add(device.getId());
        }
        return deviceIds;
    }

    public List<String> listSatelliteIds() {
        List<String> satelliteIds = new ArrayList<String>();
        for (Satellite satellite : satellites) {
            satelliteIds.add(satellite.getId());
        }
        return satelliteIds;
    }

    public void addFileToDevice(String deviceId, String filename, String content) {
        for (Device device : devices) {
            if (device.getId().equals(deviceId)) {
                device.addFile(filename, content, content.length(), true);
                break;
            }
        }
    }

    public EntityInfoResponse getInfo(String id) {
        Entity temp = searchEntityById(id);
        return new EntityInfoResponse(temp.getId(), temp.getPosition(), temp.getHeight(), temp.getType(), temp.getFilesInfo());
    }

    public Entity searchEntityById(String id) {
        for (Device device : devices) {
            if (device.getId().equals(id)) {
                return device;
            }
        }
        for (Satellite satellite : satellites) {
            if (satellite.getId().equals(id)) {
                return satellite;
            }
        }
        return null;
    }

    public void simulate() {
        for (Satellite satellite : satellites) {
            satellite.simulate(devices, satellites);
        }
        for (Device device : devices) {
            device.simulate(devices, satellites);
        }
    }

    /**
     * Simulate for the specified number of minutes.
     * You shouldn't need to modify this function.
     */
    public void simulate(int numberOfMinutes) {
        for (int i = 0; i < numberOfMinutes; i++) {
            simulate();
        }
    }

    public List<String> communicableEntitiesInRange(String id) {
        List<String> communicable = new ArrayList<String>();
        communicable.add(id);
        Entity entity = searchEntityById(id);
        if (entity instanceof Satellite) {
            Satellite satellite = (Satellite) entity;
            satellite.communicableEntitiesInRange(communicable, devices, satellites);
            communicable.remove(id);
            return communicable;
        } 
        Device device = (Device) entity;
        device.communicableEntitiesInRange(communicable, devices, satellites);
        communicable.remove(id);
        return communicable;
    }

    public void sendFile(String fileName, String fromId, String toId) throws FileTransferException {
        Entity from = searchEntityById(fromId);
        Entity to = searchEntityById(toId);
        if (communicableEntitiesInRange(fromId).contains(toId)) {
            from.sendFile(fileName, to);
        }
    }

    public void createDevice(String deviceId, String type, Angle position, boolean isMoving) {
        checkForDuplicatesId(deviceId);
        if (type.equals("HandheldDevice")) {
            devices.add(new HandheldDevice(deviceId, type, position, isMoving));
        } else if (type.equals("LaptopDevice")) {
            devices.add(new LaptopDevice(deviceId, type, position, isMoving));
        } else if (type.equals("DesktopDevice")) {
            devices.add(new DesktopDevice(deviceId, type, position, isMoving));
        }
        Collections.sort(devices, compareById);
    }

    public void createSlope(int startAngle, int endAngle, int gradient) {
        // TODO: Task 3
        // If you are not completing Task 3 you can leave this method blank :)
    }

}
