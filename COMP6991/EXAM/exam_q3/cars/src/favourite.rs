use cars::*;

fn favourite_car(brand: CarBrand) -> Box<dyn Car> {
	use CarBrand::*;

	match brand {
		Toyota => Box::new(Cressida),
		Subaru => Box::new(Liberty),
		Nissan => Box::new(Skyline),
	}
}

fn main() {
	// TODO
}
