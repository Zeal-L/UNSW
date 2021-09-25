
-- straightforward implementation of an entity

create table Projects (
	projNo  integer,
    title   text not null,
	budget  money not null,
	primary key projNo
);

-- circular references Departments<->employees
-- requires us to build the table incrementally

create table Departments (
	name    text,
    location text not null,
    phone   PhoneNumber,
--	manager integer not null references Employees(ssn),
    primary key (name)
);

create table Employees (
	ssn     integer,
	name    text not null,
	dob     date,
	worksin text not null references Departments(name),
	primary key (ssn)
);

-- required because of "circular dependency" between
-- Employees <-> Departments

alter table Departments
	add manager integer not null references Employees(ssn);

-- standard implementation of a weak entity
-- primary key involves (discriminator, strong-entity-key)

create table NextOfKin (
	name    text,  -- not null because part of primary key
	reln    text,
	phone   PhoneNumber,
	empl    integer not null,
	foreign key (empl)
	            references Employees(ssn),
	primary key (name,empl)
);

-- standard implementation of an n:m relationship

create table WorksOn (
	empl    integer,  -- not null implied by primary key
	proj    integer,  -- not null implied by primary key
    primary key (empl,proj)
);
