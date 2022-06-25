package blackout;

import static blackout.TestHelpers.assertListAreEqualIgnoringOrder;
import static unsw.utils.MathsHelper.RADIUS_OF_JUPITER;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import unsw.blackout.BlackoutController;
import unsw.utils.Angle;

@TestInstance(value = Lifecycle.PER_CLASS)
public class RelayCommunicableTests {
    @Test
    public void testCommunicableBetween3() {
        
        BlackoutController controller = new BlackoutController();
        
        controller.createSatellite("Satellite1", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(160));
        controller.createSatellite("Satellite2", "RelaySatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(190));
        controller.createSatellite("Satellite3", "TeleportingSatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(220));
        List<String> temp = controller.communicableEntitiesInRange("Satellite3");
        assertListAreEqualIgnoringOrder(Arrays.asList("Satellite1", "Satellite2"), temp);
    }

    @Test
    public void testCommunicableBetweenComplex() {
        
        BlackoutController controller = new BlackoutController();
        controller.createDevice("DeviceA", "HandheldDevice", Angle.fromDegrees(140));
        controller.createDevice("DeviceB", "HandheldDevice", Angle.fromDegrees(280));
        
        controller.createSatellite("Satellite1", "RelaySatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(150));
        controller.createSatellite("Satellite2", "RelaySatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(180));
        controller.createSatellite("Satellite3", "RelaySatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(210));
        controller.createSatellite("Satellite4", "RelaySatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(240));
        controller.createSatellite("Satellite5", "RelaySatellite", 5000 + RADIUS_OF_JUPITER, Angle.fromDegrees(270));


        List<String> temp = controller.communicableEntitiesInRange("Satellite3");
        assertListAreEqualIgnoringOrder(Arrays.asList("Satellite1", "Satellite2", "Satellite4", "DeviceA", "Satellite5", "DeviceB"), temp);
    }
    
}