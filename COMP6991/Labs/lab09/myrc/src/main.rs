use myrc_lib::MyRc;

struct Owner {
    name: String,
}

struct Gadget {
    id: i32,
    owner: MyRc<Owner>,
}

// Example used from The Book: https://doc.rust-lang.org/std/rc/index.html#examples
fn main() {
    // Create a reference-counted `Owner`.
    let gadget_owner: MyRc<Owner> = MyRc::new(
        Owner {
            name: "Gadget Man".to_string(),
        }
    );

    // Create `Gadget`s belonging to `gadget_owner`. Cloning the `Rc<Owner>`
    // gives us a new pointer to the same `Owner` allocation, incrementing
    // the reference count in the process.
    let gadget1 = Gadget {
        id: 1,
        owner: MyRc::clone(&gadget_owner),
    };
    let gadget2 = Gadget {
        id: 2,
        owner: MyRc::clone(&gadget_owner),
    };

    // Dispose of our local variable `gadget_owner`.
    drop(gadget_owner);

    // Despite dropping `gadget_owner`, we're still able to print out the name
    // of the `Owner` of the `Gadget`s. This is because we've only dropped a
    // single `Rc<Owner>`, not the `Owner` it points to. As long as there are
    // other `Rc<Owner>` pointing at the same `Owner` allocation, it will remain
    // live. The field projection `gadget1.owner.name` works because
    // `Rc<Owner>` automatically dereferences to `Owner`.
    println!("Gadget {} owned by {}", gadget1.id, gadget1.owner.name);
    println!("Gadget {} owned by {}", gadget2.id, gadget2.owner.name);

    // At the end of the function, `gadget1` and `gadget2` are destroyed, and
    // with them the last counted references to our `Owner`. Gadget Man now
    // gets destroyed as well.
}
