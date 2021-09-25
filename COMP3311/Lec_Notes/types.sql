
create type Colours as enum ('red','green','blue');
create type Mood as enum ('sad','happy','ok');

create table People (
	name text not null,
	feels Mood
);

insert into People values ('John','happy'); -- ok
insert into People values ('Andrew','angry'); -- NOT ok
insert into People values ('Tina',null); -- ok

create domain PosInt as integer check (value > 0);

create table Points (
	x PosInt default 1,
	y Posint
);

insert into Points values (3,4);    -- ok
insert into Points values (3,null); -- ok
insert into Points values (-3,4);   -- NOT ok
insert into Points(y) values (5);   -- inserts (1,5)
insert into Points values (default,5);   -- inserts (1,5)

create domain Marks as integer
		check (value between 0 and 100);

create domain CCodes as char(8)
	check (value ~ '[A-Z]{4}[0-9]{4}');

-- standard UNSW grades (FL,PS,CR,DN,HD)
CREATE TYPE Grade AS ENUM ('FL','PS','CR','DN','HD');

-- a UNSW student/staff ID
CREATE DOMAIN ZID AS integer
    CHECK (value betweem 1000000 and 9999999);

select * from People where name ~ '^John'; --John开头
select * from People where name like 'John%'; --John开头
select * from People where name ilike 'john%'; --无视大小写
select * from People where name ~* 'john'; --无视大小写

create domain PersonName as text;
--	check  (value ~ '^[A-Z][A-Za-z .,''-]+$';
