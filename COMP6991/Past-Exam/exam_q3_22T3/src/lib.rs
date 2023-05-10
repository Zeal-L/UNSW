pub struct DBMap<L, R> {
    pub data: Vec<(L, R)>
}

impl<L: std::cmp::Eq, R> DBMap<L, R> {
    pub fn merge<O>(self, mut other: DBMap<L, O>) -> DBMap<L, (R, Option<O>)> {
        let mut new_dbmap = DBMap { data: vec![] };
        for (k, v) in self.data {
            let position: Option<usize> = other.data.iter().position(|(ok, _)| k == *ok);

            if let Some(position) = position {
                new_dbmap.data.push((k, (v, Some(other.data.remove(position).1))));
            } else {
                new_dbmap.data.push((k, (v, None)));
            }

        }
        new_dbmap
    }
}
