use bmp::{consts, open};

fn main() {
    let files = std::env::args().skip(1).collect::<Vec<String>>();

    for file in files {
        println!("===== {} =====", file);

        let img = match open(&file) {
            Ok(img) => img,
            Err(e) => {
                println!("Error! {e:?}");
                continue;
            }
        };

        for (x, y) in img.coordinates() {
            let pixel = img.get_pixel(x, y);
            match pixel {
                consts::RED => print!("R"),
                consts::LIME => print!("G"),
                consts::BLUE => print!("B"),
                consts::WHITE => print!("W"),
                _ => print!("*"),
            }
            if x < img.get_width() - 1 {
                print!(" ")
            } else {
                println!()
            }
        }
    }
}
