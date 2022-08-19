package shipping;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import unsw.shipping.DiscountDecorator;
import unsw.shipping.FreeShippingDecorator;
import unsw.shipping.Lamp;
import unsw.shipping.Product;
import unsw.shipping.Shoes;

public class ProductTest {
    /*

    Uncomment this when you are ready to test the shipping exercise.
    
    @Test
    public void testDiscount() {
        // Shoes cost $90 and weigh 100 grams
        Product p1 = new Shoes();

        assertEquals(90, p1.getPrice());    

        // Give a discount of 20%
        p1 = new DiscountDecorator(p1, 20);

        assertEquals(72, p1.getPrice());    

        // Give a further discount of 25%
        p1 = new DiscountDecorator(p1, 25);
        assertEquals(54, p1.getPrice());    
    }

    
    @Test
    public void testFreeShipping() {
        // A lamp costs $50 and weighs 900 grams
        Product p1 = new Lamp();

        // Give free shipping for the lamp product if it costs more than $45 and
        // weighs less than 1kg
        Product p2 = new FreeShippingDecorator(p1, 45, 1000);

        // The lamp is eligible for the discount.
        assertEquals(0, p2.getShippingCost());    

        // ... and its weight shouldn't change
        assertEquals(900, p2.getWeight());    

        // Give free shipping for the lamp product if it costs more than $60 and
        // weighs less than 1kg
        Product p3 = new FreeShippingDecorator(p1, 60, 1000);

        // Now the lamp is no longer eligible
        assertEquals(2, p3.getShippingCost());    

        // Give free shipping for the lamp product if it costs more than $45 and
        // weighs less than 500g
        Product p4 = new FreeShippingDecorator(p1, 45, 500);

        // Now the lamp is no longer eligible
        assertEquals(2, p4.getShippingCost());    
    }

    @Test
    public void testCombinedDecorator() {
        Product p1 = new Lamp();
        // After a 5% discount a lamp is still eligible for free shipping
        Product p2 = new FreeShippingDecorator(new DiscountDecorator(p1, 5), 45, 1000);
        assertEquals(0, p2.getShippingCost());    

        // But after a 12% discount has been applied, it is no longer eligible
        // for free shipping.
        Product p3 = new FreeShippingDecorator(new DiscountDecorator(p1, 12), 45, 1000);
        assertEquals(2, p3.getShippingCost());    

        // If the discount is applied after the free shipping, however, it is
        // still eligible
        Product p4 = new DiscountDecorator(new FreeShippingDecorator(p1, 45, 1000), 10);
        assertEquals(0, p4.getShippingCost());    
    }
    
    */
}
