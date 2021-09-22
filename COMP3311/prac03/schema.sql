-- COMP3311 Prac 03 Exercise
-- Schema for Company Database
-- The first part of the exercise simply involved re-ordering the
-- data in the data.sql file so that tables were inserted in an
-- order such that there would never be REFERENCES to keys that
-- were not already inserted into the database.
--
-- Valid orders for populating tables:
--    Employee, Department, Mission, WorksFor
--    Employee, Department, WorksFor, Mission
-- The second part of the exercise required addition of CONSTRAINTs
-- to the original schema. One possible solution for this is given
-- below.
CREATE TABLE Employees (
	tfn CHAR(11) CONSTRAINT ValidTFN CHECK(tfn ~ '[0-9]{3}-[0-9]{3}-[0-9]{3}'),
	-- must have a given name
	givenName VARCHAR(30) NOT NULL,
	-- some people have only one name
	familyName VARCHAR(30),
	--7*24
	hoursPweek FLOAT CONSTRAINT ValidHPW CHECK (
		hoursPweek >= 0
		AND hoursPweek <= 168
	),
	PRIMARY KEY (tfn)
);

CREATE TABLE Departments (
	-- [[:digit:]] == [0-9]
	id CHAR(3) CONSTRAINT ValidDeptId CHECK (id ~ '[[:digit:]]{3}'),
	NAME VARCHAR(100) UNIQUE,
	manager CHAR(11) CONSTRAINT ValidEmployee REFERENCES Employees(tfn),
	PRIMARY KEY (id)
);

CREATE TABLE DeptMissions (
	department CHAR(3) CONSTRAINT ValidDepartment REFERENCES Departments(id),
	keyword VARCHAR(20),
	PRIMARY KEY (department, keyword)
);

CREATE TABLE WorksFor (
	employee CHAR(11) CONSTRAINT ValidEmployee REFERENCES Employees(tfn),
	department CHAR(3) CONSTRAINT ValidDepartment REFERENCES Departments(id),
	percentage FLOAT CONSTRAINT ValidPercentage CHECK (
		percentage >= 0.0
		AND percentage <= 100.0
	),
	PRIMARY KEY (employee, department)
);