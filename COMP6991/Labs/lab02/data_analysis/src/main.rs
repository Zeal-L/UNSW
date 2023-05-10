use std::collections::HashMap;
use csv::ReaderBuilder;
use serde::Deserialize;

const ENROLMENTS_PATH: &str = "enrolments.psv";

#[derive(Deserialize)]
struct Record {
    course_code: String,
    zid: u32,
    name: String,
    program: String,
    plan: String,
    wam: f32,
    session: String,
    birthdate: String,
    sex: String,
}

fn read_enrolments(path: &str) -> Vec<Record> {
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b'|')
        .from_path(path)
        .expect("Error opening file");

    let header = csv::StringRecord::from(vec!["course_code", "zid", "name", "program", "plan", "wam", "session", "birthdate", "sex"]);

    let mut records: Vec<Record> = Vec::new();

    for record in reader.records() {
        let info: Record = record.unwrap().deserialize(Some(&header)).unwrap();
        records.push(info);
    }
    records
}

fn count_unique_students(records: &Vec<Record>) -> usize {
    let mut students = Vec::new();
    for record in records {
        if !students.contains(&record.zid) {
            students.push(record.zid);
        }
    }
    students.len()
}

fn get_most_common_course(records: &Vec<Record>) -> (String, u32) {
    let mut courses = HashMap::new();
    for record in records {
        let course_count = courses.entry(record.course_code.clone()).or_insert(0);
        *course_count += 1;
    }
    let course = courses.iter().max_by_key(|&(_, v)| v).unwrap().clone();
    (course.0.to_string(), *course.1)
}

fn get_least_common_course(records: &Vec<Record>) -> (String, u32) {
    let mut courses = HashMap::new();
    for record in records {
        let course_count = courses.entry(record.course_code.clone()).or_insert(0);
        *course_count += 1;
    }
    let course = courses.iter().min_by_key(|&(_, v)| v).unwrap().clone();
    (course.0.to_string(), *course.1)
}

fn get_average_wam(records: &Vec<Record>) -> f32 {
    let mut total_wam = 0.0;
    let mut students = Vec::new();
    for record in records {
        if !students.contains(&record.zid) {
            students.push(record.zid);
            total_wam += record.wam;
        }
    }
    (total_wam / students.len() as f32 * 100.0).round() / 100.0
}

fn main() {
    let records = read_enrolments(ENROLMENTS_PATH);
    let (mcc_code, mcc_num) = get_most_common_course(&records);
    let (lcc_code, lcc_num) = get_least_common_course(&records);
    println!("Number of students: {}", count_unique_students(&records));
    println!("Most common course: {} with {} students", mcc_code, mcc_num);
    println!("Least common course: {} with {} students", lcc_code, lcc_num);
    println!("Average WAM: {}", get_average_wam(&records));
}
