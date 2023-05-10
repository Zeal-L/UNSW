use std::ops::Deref;

struct Inner<T> {
    refcount: usize,
    data: T,
}

pub struct MyRc<T> {
    inner: *mut Inner<T>,
}

impl<T> MyRc<T> {
    pub fn new(value: T) -> Self {
        // TODO: Create a MyRc. You will need to:
        //  - use Box::into_raw to create an Inner
        //  - set refcount to an appropriate value.
        MyRc {
            inner: Box::into_raw(Box::new(Inner {
                refcount: 1,
                data: value,
            })),
        }
    }
}

impl<T> Clone for MyRc<T> {
    fn clone(&self) -> Self {
        // TODO: Increment the refcount,
        // and return another MyRc<T> by copying the
        // inner struct of this MyRc.
        let mut inner = unsafe { &mut *self.inner };
        inner.refcount += 1;
        MyRc { inner: self.inner }
    }
}

impl<T> Drop for MyRc<T> {
    fn drop(&mut self) {
        // TODO: Decrement the refcount..
        // If it's 0, drop the Rc. You will need to use
        // Box::from_raw to do this.
        let mut inner = unsafe { &mut *self.inner };
        inner.refcount -= 1;
        if inner.refcount == 0 {
            unsafe {
                drop(Box::from_raw(self.inner));
            }
        }
    }
}

impl<T> Deref for MyRc<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // TODO: Return a &T.
        unsafe { &(*self.inner).data }
    }
}
