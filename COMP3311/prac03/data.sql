-- COMP3311 Prac 03 Exercise
-- Populate the database for the simple company schema
-- This version has the data in the correct order

insert into Employees values ('777-654-321','Yusif','Budianto',40.0);
insert into Employees values ('123-987-654','Maria','Orlowska',40.0);
insert into Employees values ('323-626-929','Tom','Robbins',35.0);
insert into Employees values ('993-893-864','Susan','Ryan',60.0);
insert into Employees values ('419-813-573','Max','Schmidt',40.0);
insert into Employees values ('222-333-444','Pradeep','Sharma',30.0);
insert into Employees values ('123-234-456','John','Smith',40.0);
insert into Employees values ('632-647-973','Steven','Smooth',45.0);
insert into Employees values ('747-400-123','Adam','Spencer',50.0);
insert into Employees values ('326-888-711','Walter','Wong',50.0);

insert into Departments values ('001','Administration','123-234-456');
insert into Departments values ('002','Sales','222-333-444');
insert into Departments values ('003','Research','326-888-711');

insert into DeptMissions values ('001','innovation');
insert into DeptMissions values ('001','reliability');
insert into DeptMissions values ('001','profit');
insert into DeptMissions values ('002','customer-focus');
insert into DeptMissions values ('002','growth');
insert into DeptMissions values ('003','innovation');
insert into DeptMissions values ('003','technology');

insert into WorksFor values ('777-654-321','003',100);
insert into WorksFor values ('123-987-654','003',100);
insert into WorksFor values ('323-626-929','001',50);
insert into WorksFor values ('323-626-929','002',50);
insert into WorksFor values ('993-893-864','001',100);
insert into WorksFor values ('419-813-573','003',100);
insert into WorksFor values ('222-333-444','002',100);
insert into WorksFor values ('123-234-456','001',100);
insert into WorksFor values ('632-647-973','002',100);
insert into WorksFor values ('747-400-123','001',10);
insert into WorksFor values ('747-400-123','002',90);
insert into WorksFor values ('326-888-711','003',100);
