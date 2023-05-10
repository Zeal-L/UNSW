use bmp::{Image, Pixel};

fn main() {
    let width = 200;
    let height = 200;
    let mut img = Image::new(width, height);

    for (x, y) in img.coordinates() {

        let half = width as f32 / 2.0;
        let quarter = width as f32 / 4.0;

        let a = (x as f32 - half) / quarter;
        let b = (y as f32 - half) / quarter;
        let c = (a * a + b * b - 1.0).powf(3.0) - a * a * b * b * b;

        img.set_pixel(x, y,
            if c <= 0.0 {
                Pixel::new(255, 0, 0)
            } else {
                Pixel::new(255, 255, 255)
            }
        );
    }

    match img.save("img.bmp") {
        Ok(_) => println!("Image saved successfully"),
        Err(e) => println!("Error: {}", e),
    }
}
