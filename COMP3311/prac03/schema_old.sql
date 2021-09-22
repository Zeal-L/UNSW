-- COMP3311 Prac 03 Exercise
-- Schema for simple company database

create table Employees (
	tfn         char(11),
	givenName   varchar(30),
	familyName  varchar(30),
	hoursPweek  float
);

create table Departments (
	id          char(3),
	name        varchar(100),
	manager     char(11)
);

create table DeptMissions (
	department  char(3),
	keyword     varchar(20)
);

create table WorksFor (
	employee    char(11),
	department  char(3),
	percentage  float
);
