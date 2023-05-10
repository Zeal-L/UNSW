use std::{collections::HashMap, rc::Rc};

pub struct Cache<Key, Value> {
    calculator: Box<dyn FnMut(&Key) -> Value + 'static>,
    cache_map: HashMap<Key, Rc<Value>>,
}

impl<Key: Eq + std::hash::Hash + Clone, Value: Clone> Cache<Key, Value> {
    pub fn new<F>(calculator: F) -> Self
        where F: FnMut(&Key) -> Value + 'static
    {
        Cache {
            calculator: Box::new(calculator),
            cache_map: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: Key) -> Rc<Value> {
        if let Some(value) = self.cache_map.get(&key) {
            Rc::clone(value)
        } else {
            let value = Rc::new((self.calculator)(&key));
            self.cache_map.insert(key.clone(), Rc::clone(&value));
            value
        }
    }
}