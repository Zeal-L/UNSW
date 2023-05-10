// You should NOT be constructing
// a new ticket, so you should never use this directly.
#[derive(Debug)]
struct Ticket;

struct Person {
    name: String,
    ticket: Option<Ticket>,
}

fn main() {
    let entry_pass = Ticket;
    let shrey_name = String::from("shrey");
    let tom_name = String::from("tom");

    // Only change code past this line!
    let shrey_upper_name = to_uppercase(shrey_name);
    let tom_upper_name = to_uppercase(tom_name);

    let shrey = Person {
        name: shrey_upper_name,
        ticket: Some(entry_pass),
    };

    let tom = Person {
        name: tom_upper_name,
        ticket: None,
    };

    let (shrey, tom) = move_ticket(shrey, tom);

    // do not change these lines
    println!("{} ticket: {:?}", shrey.name, shrey.ticket);
    println!("{} ticket: {:?}", tom.name, tom.ticket);
}


fn to_uppercase(s: String) -> String {
    s.to_uppercase()
}

// Do not change the function signature
fn move_ticket(mut from: Person, mut to: Person) -> (Person, Person) {
    // TODO:
    // the ticket should be moved to the "from" person
    // to the 'to' person
    // for now, return the people UNCHANGED

    let temp = from.ticket;
    from.ticket = to.ticket;
    to.ticket = temp;
    (from, to)
}
