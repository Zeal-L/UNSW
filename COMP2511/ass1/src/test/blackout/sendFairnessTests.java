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
public class sendFairnessTests {
    @Test
    public void testDeviceSendMultipleFileAtSameTime() {
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(310));
        controller.createDevice("DeviceC", "HandheldDevice", Angle.fromDegrees(320));

        String msg = "123456789000015";
        controller.addFileToDevice("DeviceC", "FileA", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileB", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileB", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileC", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileC", "DeviceC", "Satellite1"));
        
        controller.simulate(1);

        assertEquals(new FileInfoResponse("FileA", "12345", msg.length(), false), controller.getInfo("Satellite1").getFiles().get("FileA"));
        assertEquals(new FileInfoResponse("FileB", "12345", msg.length(), false), controller.getInfo("Satellite1").getFiles().get("FileB"));
        assertEquals(new FileInfoResponse("FileC", "12345", msg.length(), false), controller.getInfo("Satellite1").getFiles().get("FileC"));
    }

    @Test
    public void testFairnessForSatelliteSend() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(310));
        controller.createDevice("DeviceC", "HandheldDevice", Angle.fromDegrees(320));

        String msg = "123456789000015";
        controller.addFileToDevice("DeviceC", "FileA", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileB", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileB", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileC", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileC", "DeviceC", "Satellite1"));
        
        controller.simulate(3);
        
        assertDoesNotThrow(() -> controller.sendFile("FileA", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileB", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileC", "Satellite1", "Satellite2"));

        controller.simulate(1);

        assertEquals(new FileInfoResponse("FileA", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileA"));
        assertEquals(new FileInfoResponse("FileB", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileB"));
        assertEquals(new FileInfoResponse("FileC", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileC"));
    }

    @Test
    public void testFairnessForSatelliteSendMultiple() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(310));
        controller.createDevice("DeviceC", "HandheldDevice", Angle.fromDegrees(320));

        String msg = "123456789000015";
        controller.addFileToDevice("DeviceC", "FileA", "123");
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileB", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileB", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileC", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileC", "DeviceC", "Satellite1"));
        
        controller.simulate(3);
        
        assertDoesNotThrow(() -> controller.sendFile("FileA", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileB", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileC", "Satellite1", "Satellite2"));

        controller.simulate(2);

        assertEquals(new FileInfoResponse("FileA", "123", 3, true), controller.getInfo("Satellite2").getFiles().get("FileA"));
        assertEquals(new FileInfoResponse("FileB", "12345678", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileB"));
        assertEquals(new FileInfoResponse("FileC", "12345678", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileC"));
    }

    @Test
    public void testFairnessBetweenMultipleSatellite() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite3", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(310));
        controller.createDevice("DeviceC", "HandheldDevice", Angle.fromDegrees(320));

        String msg = "12345";
        controller.addFileToDevice("DeviceC", "FileA", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileB", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileB", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileC", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileC", "DeviceC", "Satellite3"));
        
        controller.simulate(3);
        
        assertDoesNotThrow(() -> controller.sendFile("FileA", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileB", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileC", "Satellite3", "Satellite2"));

        controller.simulate(1);

        assertEquals(new FileInfoResponse("FileA", msg, msg.length(), true), controller.getInfo("Satellite2").getFiles().get("FileA"));
        assertEquals(new FileInfoResponse("FileB", msg, msg.length(), true), controller.getInfo("Satellite2").getFiles().get("FileB"));
        assertEquals(new FileInfoResponse("FileC", msg, msg.length(), true), controller.getInfo("Satellite2").getFiles().get("FileC"));
    }

    @Test
    public void testFairnessBetweenMultipleSatellite2() {
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite2", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createSatellite("Satellite3", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(320));
        controller.createDevice("DeviceB", "LaptopDevice", Angle.fromDegrees(310));
        controller.createDevice("DeviceC", "HandheldDevice", Angle.fromDegrees(320));

        String msg = "12345";
        controller.addFileToDevice("DeviceC", "FileA", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileA", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileB", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileB", "DeviceC", "Satellite1"));
        controller.addFileToDevice("DeviceC", "FileC", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileC", "DeviceC", "Satellite3"));
        controller.addFileToDevice("DeviceC", "FileD", msg);
        assertDoesNotThrow(() -> controller.sendFile("FileD", "DeviceC", "Satellite3"));
        
        controller.simulate(4);
        
        assertDoesNotThrow(() -> controller.sendFile("FileA", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileB", "Satellite1", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileC", "Satellite3", "Satellite2"));
        assertDoesNotThrow(() -> controller.sendFile("FileD", "Satellite3", "Satellite2"));

        controller.simulate(1);

        assertEquals(new FileInfoResponse("FileA", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileA"));
        assertEquals(new FileInfoResponse("FileB", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileB"));
        assertEquals(new FileInfoResponse("FileC", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileC"));
        assertEquals(new FileInfoResponse("FileD", "123", msg.length(), false), controller.getInfo("Satellite2").getFiles().get("FileD"));
    }


}