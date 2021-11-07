-- add foreign key constraints to Course_enrolments

alter table course_enrolments
  add constraint student_enrol_fk
  foreign key (student) references students(id);
alter table course_enrolments
  add constraint course_enrol_fk
  foreign key (course) references courses(id);

-- fix owner of 3707

update programs set offeredby = 112 where id = 3707;

-- fix marks for Thesis A (COMP4930)

update course_enrolments set mark=75, grade='CR'
where  course in (select id  from courses where subject=12392)
       and mark is not null
;

