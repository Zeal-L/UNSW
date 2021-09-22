-- COMP3311 Prac 03 Exercise
-- Populate the database of the simple company schema
-- This file contains entirely invalid tuples
-- None of these should be inserted once your constraints are correct

insert into Employees values ('abc-123-def','John','Smith',40);
insert into Employees values ('123-987-654','Jane','Brown',30);
insert into Employees values ('321-987-654','Joan','Woods',300);
insert into Employees values ('321-224-335','Alice','Smith',-5);
insert into Employees values ('321-224-335',null,'Smith',25);
insert into Departments values ('xyz','Blah Blah','777-654-321');
insert into Departments values ('004','Sales','777-654-321');
insert into Departments values ('002','Blah Blah','123-234-456');
insert into Departments values ('005','Blee Blee','999-888-777');
insert into DeptMissions values ('007','danger');
insert into DeptMissions values ('002',null);
insert into WorksFor values ('747-400-123',null,20);
insert into WorksFor values ('987-654-321','003',100);
insert into WorksFor values ('323-626-929','909',10);
insert into WorksFor values ('323-626-929','003',110);
insert into WorksFor values ('323-626-929','003',-10);
