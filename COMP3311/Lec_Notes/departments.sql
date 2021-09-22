create table Employees (
	ssn     integer,
	name    text not null,
	dob     date,
	primary key (ssn)
);

create table NextOfKin (
	name    text,
    reln    text,
	phone   integer,
	empl    integer not null,
	foreign key (empl)
	            references Employees(ssn),
	primary key (name,empl)
);
