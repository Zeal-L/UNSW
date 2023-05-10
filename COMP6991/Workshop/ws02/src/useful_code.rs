use std::collections::HashMap;

#[derive(Debug, Hash, PartialEq, Eq)]
enum TimeOfDay {
    Morning,
    Midday,
    Evening,
    Midnight,
    Total
}

#[derive(Debug)]
struct Entry {
    time_period: String,
    station: String,
    entries: HashMap<TimeOfDay, i32>,
    exits: HashMap<TimeOfDay, i32>,
    latitude: f64,
    longitude: f64,
}

fn convert_csventry_to_entry(csv_entry: &CSVEntry) -> Entry {
    let mut entry = Entry {
        time_period: csv_entry.time_period.clone(),
        station: csv_entry.station.clone(),
        entries: HashMap::new(),
        exits: HashMap::new(),
        latitude: csv_entry.latitude,
        longitude: csv_entry.longitude
    };

    if let Some(e) = csv_entry.entries_morning {
        entry.entries.insert(TimeOfDay::Morning, e);
    }
    if let Some(e) = csv_entry.entries_midday {
        entry.entries.insert(TimeOfDay::Midday, e);
    }
    if let Some(e) = csv_entry.entries_evening {
        entry.entries.insert(TimeOfDay::Evening, e);
    }
    if let Some(e) = csv_entry.entries_midnight {
        entry.entries.insert(TimeOfDay::Midnight, e);
    }
    if let Some(e) = csv_entry.entries_total {
        entry.entries.insert(TimeOfDay::Total, e);
    }

    if let Some(e) = csv_entry.exits_morning {
        entry.exits.insert(TimeOfDay::Morning, e);
    }
    if let Some(e) = csv_entry.exits_midday {
        entry.exits.insert(TimeOfDay::Midday, e);
    }
    if let Some(e) = csv_entry.exits_evening {
        entry.exits.insert(TimeOfDay::Evening, e);
    }
    if let Some(e) = csv_entry.exits_midnight {
        entry.exits.insert(TimeOfDay::Midnight, e);
    }
    if let Some(e) = csv_entry.exits_total {
        entry.exits.insert(TimeOfDay::Total, e);
    }

    entry

}
