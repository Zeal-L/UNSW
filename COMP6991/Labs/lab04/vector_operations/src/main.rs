#[derive(Clone, Copy, Debug)]
/// A struct representing a 3D vector
struct Vec3 {
    /// The x component of the vector
    x: f64,
    /// The y component of the vector
    y: f64,
    /// The z component of the vector
    z: f64,
}

impl Vec3 {
    /// Create a new vector with the given components
    /// # Examples
    /// ```
    /// let v = Vec3::new(1.0, 2.0, 3.0);
    /// ```
    fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }
}

// define what the Addition operator does for Vec3
impl std::ops::Add for Vec3 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            x: self.x + rhs.x,
            y: self.y + rhs.y,
            z: self.z + rhs.z,
        }
    }
}

// YOUR TASK:
//  - Implement the `Sub` behaviour for `Vec3`
impl std::ops::Sub for Vec3 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            x: self.x - rhs.x,
            y: self.y - rhs.y,
            z: self.z - rhs.z,
        }
    }
}
//  - Implement the `Mul` behaviour for `Vec3`
impl std::ops::Mul for Vec3 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self {
            x: self.x * rhs.x,
            y: self.y * rhs.y,
            z: self.z * rhs.z,
        }
    }
}
//  - Implement the `Div` behaviour for `Vec3`
impl std::ops::Div for Vec3 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        Self {
            x: self.x / rhs.x,
            y: self.y / rhs.y,
            z: self.z / rhs.z,
        }
    }
}

fn main() {
    let v1 = Vec3::new(1.0, 2.0, 3.0);
    let v2 = Vec3::new(4.0, 5.0, 6.0);

    println!("v1 = {:?}", v1);
    println!("v2 = {:?}", v2);

    println!("v1 + v2 = {:?}", v1 + v2);
    println!("v1 - v2 = {:?}", v1 - v2);
    println!("v1 * v2 = {:?}", v1 * v2);
    println!("v1 / v2 = {:?}", v1 / v2);
}
