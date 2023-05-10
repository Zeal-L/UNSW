
#[derive(Debug)]
enum Owner {
    Individual(Person),
    Bank(String),
}

#[derive(Debug)]
struct Person {
    name: String,
    age: u8,
}

#[derive(Debug)]
struct House {
    house_id: i32,
    address: String,
    price: i32,
    owner: Owner,
}

fn main() {

    let dan = Person {
        age: 18,
        name: "Dan".to_string(),
    };

    let mitch = Person {
        age: 21,
        name: "Mitch".to_string(),
    };

    let john = Person {
        age: 34,
        name: "John".to_string(),
    };

    let mut house1 = House {
        house_id: 1,
        address: "123 Main St".to_string(),
        price: 1000000,
        owner: Owner::Bank("Commonwealth Bank".to_string()),
    };

    let mut house2 = House {
        house_id: 2,
        address: "456 Main St".to_string(),
        price: 2000000,
        owner: Owner::Individual(mitch),
    };

    let house3 = House {
        house_id: 3,
        address: "789 Main St".to_string(),
        price: 3000000,
        owner: Owner::Bank("Bank of Melbourne".to_string()),
    };

    // Your code starts here!!

    // TODO: set the owner of house1 to John
    // This means: pass in a mutable reference to house1
    // and a new Owner::Individual(john) to the buy_house function
    buy_house(&mut house1, Owner::Individual(john));

    // TODO: set the owner of house2 to the Bank of Melbourne
    // This means: pass in a mutable reference to House2
    // and a new Owner::Bank("Bank of Melbourne".to_string()) to the buy_house function
    buy_house(&mut house2, Owner::Bank("Bank of Melbourne".to_string()));


    // leave these here :)
    println!("House1 is owned by: {:?}", house1.owner);
    println!("House2 is owned by: {:?}", house2.owner);
    println!("House3 is owned by: {:?}", house3.owner);
}

// TODO: fill out the function parameter types!
fn buy_house(house: &mut House, buyer: Owner) {
    house.owner = buyer;
}
