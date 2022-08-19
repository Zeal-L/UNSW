## Lab 10 - Revision Exercise - Shipping Discounts

The class `Product` represents a product in an online store with a price and weight. The weight is used to calculate the shipping cost. Using the  Decorator Pattern:

Implement `DiscountDecorator` that discounts the price of a product by a given percentage. Multiple discounts are applied cumulatively (e.g. if 20% discount on $100 gives a price of $80, a further discount of 20% would give a price of $64).
Implement FreeShippingDecorator that makes shipping free for products over a given price and under a given weight. Note that, if this decorator is applied to a discounted product, whether or not it qualifies for free shipping depends on the discounted price.

The tests in `test/shipping/ProductTest` will guide you in completing these. 