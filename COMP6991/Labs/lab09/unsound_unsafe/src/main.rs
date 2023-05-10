use std::ptr::null_mut as null;

/// Delete the first node in a linked list.
/// This function will return the new list.
///
/// If the list is empty (i.e. `list == null()`),
/// then this function should return `null()`.
///
/// # Safety
///
/// The list must be a valid linked list,
/// as is defined on the type `List`.
///
/// The list may have zero or more elements.
///
unsafe fn list_delete_first(list: *mut List<i32>) -> *mut List<i32> {
    // /!\ SAFETY: The list must be a valid linked list,
    //             so we get a pointer to the second node
    //             for later!
    //             TODO: hmm... is this definitely sound?
    if list == null() {
        return null();
    }
    let next = unsafe { (*list).next };

    // /!\ SAFETY: The list must be a valid linked list,
    //             so we can free the first node.
    //             TODO: hmm... is this definitely sound?
    //                      ... the first node exists... right?
    unsafe { free_node(list); }

    return next;
}


/////////////////////////////////////////
// DO NOT MODIFY CODE BELOW THIS POINT //
/////////////////////////////////////////


fn main() {
    let list = my_linked_list();

    // /!\ SAFETY: my_linked_list() always returns a valid
    //             linked list, which fulfils the safety
    //             preconditions of all other functions!
    unsafe {
        print_list(list);
        let list = list_delete_first(list);
        print_list(list);

        free_list(list);
    }
}

/// A linked list node.
///
/// Note that any individual node may also
/// represent a list in its entirety, due to
/// the nature of how linked lists work.
///
/// # Validity
///
/// A linked list (of type *mut List<T>)
/// is considered valid if it is either:
///
/// 1. Null (i.e. list == null())
///
/// 2. A heap allocated value
///    (constructed from a `Box`),
///    whose `next` field is
///    *also* a valid linked list.
struct List<T> {
    value: T,
    next: *mut List<T>,
}

fn my_linked_list() -> *mut List<i32> {
    let nums = std::env::args()
        .skip(1)
        .map(|arg| arg.parse::<i32>().expect(&format!("Failed to parse {arg} as i32")))
        .collect::<Vec<_>>();

    let mut curr_node = None;
    for value in nums.into_iter().rev() {
        curr_node = Some(Box::into_raw(Box::new(
            List {
                value,
                next: curr_node.unwrap_or_else(null),
            }
        )));
    }

    curr_node.unwrap_or_else(null)
}

/// Print a linked list
///
/// # Safety
///
/// The list must be a valid linked list,
/// as is defined on the type `List`.
///
/// The list may have zero or more elements.
unsafe fn print_list(list: *mut List<i32>) {
    println!("=== PRINTING LIST ===");
    let mut curr = list;
    while curr != null() {
        // /!\ SAFETY: `curr` is not `null`,
        //             therefore it is safe to dereference
        //             and access its fields.
        println!("{}", unsafe { (*curr).value });

        // /!\ SAFETY: ... as above
        curr = unsafe { (*curr).next };
    }
    println!("=====================");
}

/// Free a linked list node
///
/// # Safety
///
/// The node must be a heap allocated value,
/// originally constructed from a `Box`.
/// Specifically, it must also *not* be `null`.
///
/// The node must currently be valid to *own*.
///
/// There are no requirements on `next`.
unsafe fn free_node(node: *mut List<i32>) {
    // /!\ SAFETY: The node is a heap allocated value
    //             constructed from a `Box`, that is
    //             currently candidate to own.
    //
    //             Therefore, `Box::from_raw` is sound.
    drop(unsafe { Box::from_raw(node) });
}

/// Free a linked list
///
/// # Safety
///
/// The list must be a valid linked list,
/// as is defined on the type `List`.
///
/// The list may have zero or more elements.
unsafe fn free_list(list: *mut List<i32>) {
    let mut curr = list;
    while curr != null() {
        let to_free = curr;

        // /!\ SAFETY: `curr` is not `null`,
        //             therefore it is safe to dereference
        //             and access its fields.
        curr = unsafe { (*curr).next };

        // /!\ SAFETY: `to_free` came from `curr`,
        //             which was a non-null linked list
        //             node. Due to the requirements on
        //             `List`, `to_free` must be sound
        //             to free with `free_node`.
        unsafe { free_node(to_free) };
    }
}
