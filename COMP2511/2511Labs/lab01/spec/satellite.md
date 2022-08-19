## Lab 01 - Core Exercise - Satellite 🛰️

A satellite is a moon, planet or machine that orbits a planet or star. In this exercise, you will create an class that represents a satellite, and using this class create a series of Satellite object instances.

<img src='imgs/sat.jpg' width="700" />

Satellites have the following attributes/characteristics:

* A `name` (String)
* A `height` in kilometres above the centre of the earth (integer)
* A `velocity` in metres per second (double)
* A `position`, which is an angle `θ` in **degrees** of the satellite relative to the x-axis, anticlockwise. 
* All of the above attributes can be retrieved using a *getter* function and set using a *setter* function
* The position of the satellite can be retrieved in radians as well as degrees
* The angular velocity of the satellite, (radians per second) can be found as well as the linear velocity (metres per second)
* Given a length of time in seconds, the distance the satellite has travelled can be found.

You have been given a series of function definitions inside `src/satellite/Satellite.java`. Implement these functions according to the docstrings and above requirements.

Once you have done this, write a `main` method that does the following:
* Creates Satellite A, which is `10000 km` above the centre of the earth, with a velocity of `55` metres per second and at `θ = 122`.
* Creates Satellite B, which is `5438 km` above the centre of the earth, with a velocity of `234` **kilometres** per second and at `θ = 0`.
* Creates Satellite C, which is `9029 km` above the centre of the earth, with a velocity of `0` metres per second and at `θ = 284`.
* For Satellite A, print out `I am {name} at position {theta} degrees, {height} km above the centre of the earth and moving at a velocity of {velocity} metres per second`
* Change Satellite A's height to `9999`
* Change Satellite B's angle to `45`
* Change Satellite C's velocity to `36.5 mps`
* Print out Satellite A's position in radians
* Print out Satellite B's angular velocity
* Print out the distance Satellite C travels after 2 minutes.

### Expected Output

```
I am Satellite A at position 122.0 degrees, 10000 km above the centre of the earth and moving at a velocity of 55.0 metres per second
2.129301687433082
0.04303052592865024
4380.0
```

<details>

<summary>

### Tips

</summary>

1. You will need to store all of the attributes as fields in the class. This can be done above your constructor by declaring each field. For example:

```java
private String name;
```

You don't have to set the field to be any particular value (they will be `null` by default for objects, and `0` for primitive data types like integers).

2. In the constructor, initialise all of the fields to the parameters using the syntax:

```java
this.name = name;
```

3. You can convert between degrees and radians using `Math.toDegrees(theta)` and `Math.toRadians(theta)`.

4. The formula for conversion between linear and angular velocity is `linear velocity = radius * angular velocity` i.e. `angular velocity = linear velocity / radius`. Think about what the 'radius' is here!

</details>
