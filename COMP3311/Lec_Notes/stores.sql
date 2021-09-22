create table Customers (
	custNo  integer check (custNo > 0),
--	name    varchar(100),
	name    text not null,
	address text not null, -- null != ''
	fave    text references Stores(phone),
	primary key (custNo)
--	primary key (name,address)
);

create table Accounts (
	acctNo   integer check (acctNo > 0),
	balance  float,
	usedAt   text not null,
	foreign key (usedAt)
                references Stores(phone),
	primary key (acctNo)
);

create table Stores (
	phone    text, -- primary key,
	address  text not null,
	primary key (phone)
);

create table Has (
	customer integer,
	account  integer,
    foreign key (customer)
	            references Customers(custNo),
    foreign key (account)
	            references Accounts(acctNo),
	primary key (customer,account)
);
