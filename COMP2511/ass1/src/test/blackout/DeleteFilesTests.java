package blackout;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static unsw.utils.MathsHelper.RADIUS_OF_JUPITER;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import unsw.blackout.BlackoutController;
import unsw.response.models.FileInfoResponse;
import unsw.utils.Angle;

@TestInstance(value = Lifecycle.PER_CLASS)
public class DeleteFilesTests {
    @Test
    public void testDeleteFilesOutOfRange() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(110));
        
        controller.createDevice("DeviceA", "LaptopDevice", Angle.fromDegrees(90));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(310));
        
        String msg = "1".repeat(150);
        controller.addFileToDevice("DeviceA", "FileA", msg);

        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceA", "Satellite1"));
        
        controller.simulate(5);

        assertEquals(null, controller.getInfo("Satellite1").getFiles().get("FileA"));
    }

    @Test
    public void testDeleteFilesOutOfRangeMultiple() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(110));
        
        controller.createDevice("DeviceA", "LaptopDevice", Angle.fromDegrees(90));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(100));
        
        String msg = "1".repeat(99);
        controller.addFileToDevice("DeviceA", "FileA", msg);
        controller.addFileToDevice("DeviceB", "FileB", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceA", "Satellite1"));
        assertDoesNotThrow(() -> controller.sendFile("FileB", "DeviceB", "Satellite1"));
        
        controller.simulate(5);

        assertEquals(null, controller.getInfo("Satellite1").getFiles().get("FileA"));
        assertEquals(new FileInfoResponse("FileB", "1".repeat(75), msg.length(), false), controller.getInfo("Satellite1").getFiles().get("FileB"));
    }

    @Test
    public void testDeleteFilesOutOfRangeSendFromSetellite() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(110));
        
        controller.createDevice("DeviceA", "LaptopDevice", Angle.fromDegrees(90));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(90));
        
        String msg = "1".repeat(45);
        controller.addFileToDevice("DeviceA", "FileA", msg);
        
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceA", "Satellite1"));

        controller.simulate(3);

        assertDoesNotThrow(() -> controller.sendFile("FileA", "Satellite1", "DeviceB"));

        controller.simulate(2);
    
        assertEquals(null, controller.getInfo("DeviceB").getFiles().get("FileA"));
        
    }
    @Test
    public void testdeleteAfterTeleport() {
    
        BlackoutController controller = new BlackoutController();

        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(179));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(180));
        

        String msg = "a".repeat(25) + "t".repeat(25);
        controller.addFileToDevice("DeviceB", "FileAlpha", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileAlpha", "DeviceB", "Satellite1"));

        controller.simulate(3);

        assertEquals(new FileInfoResponse("FileAlpha", "a".repeat(25), 25, true), controller.getInfo("DeviceB").getFiles().get("FileAlpha"));
    }

    @Test
    public void testdeleteAfterTeleportComplex() {
    
        BlackoutController controller = new BlackoutController();

        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(175));
        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(170));

        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(180));
        controller.createDevice("DeviceC", "LaptopDevice", Angle.fromDegrees(180));
        

        String msg = "a".repeat(15) + "t".repeat(15) + "a".repeat(15);
        controller.addFileToDevice("DeviceB", "FileAlpha", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileAlpha", "DeviceB", "Satellite1"));

        controller.simulate(6);


        assertDoesNotThrow(() -> controller.sendFile("FileAlpha", "Satellite1", "Satellite2"));

        assertDoesNotThrow(() -> controller.sendFile("FileAlpha", "Satellite1", "DeviceC"));

        controller.simulate(2);


        assertEquals(new FileInfoResponse("FileAlpha", "a".repeat(30), 30, true), controller.getInfo("DeviceC").getFiles().get("FileAlpha"));
        assertEquals(new FileInfoResponse("FileAlpha", "a".repeat(30), 30, true), controller.getInfo("Satellite2").getFiles().get("FileAlpha"));
    }

    @Test
    public void testdeleteAfterTeleportComplex2() {
    
        BlackoutController controller = new BlackoutController();

        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(165));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(165));

        

        String msg = "a".repeat(15) + "t".repeat(15) + "a".repeat(15);
        controller.addFileToDevice("DeviceB", "FileAlpha", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileAlpha", "DeviceB", "Satellite1"));

        controller.simulate(5);

        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(179.5));
        assertDoesNotThrow(() -> controller.sendFile("FileAlpha", "Satellite1", "Satellite2"));


        controller.simulate(1);
        
        assertEquals(new FileInfoResponse("FileAlpha", "a".repeat(30), 30, true), controller.getInfo("Satellite2").getFiles().get("FileAlpha"));
    }

}