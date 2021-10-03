-- ER mapping
create table Students (
	sid integer primary key,
	name text not null,
	address text
);
create table Undergrads (
	sid integer not null references Students(sid),
	degree text,
	primary key (sid)
);
create table Masters (
	sid integer not null references Students(sid),
	primary key (sid)
);
create table PhDs (
	sid integer not null references Students(sid),
	thesis text,
	primary key (sid)
);

-- Single-table mapping (overlapping)
create table Students (
	sid integer primary key,
	name text not null,
	address text,
	degree text,
	is_masters boolean,
	thesis text
);

-- Single-table mapping (disjoint)
create table Students (
	sid integer primary key,
	name text not null,
	address text,
	stype char(2) not null check (stype in ('UG','PG','RS')),
	degree text,
	thesis text,
	constraint real_disjoint check
		(stype = 'UG' and degree is not null and thesis is null)
		or
		(stype = 'PG' and thesis is null and degree is null)
		or
		(stype = 'RS' and degree is null and thesis is not null)
);

-- OO mapping
create table Students (
	sid integer primary key,
	name text not null,
	address text
);
create table Undergrads (
	sid integer primary key,
	name text not null,
	address text
	degree text
);
create table Masters (
	sid integer primary key,
	name text not null,
	address text
);
create table PhDs (
	sid integer primary key,
	name text not null,
	address text
	thesis text
);
