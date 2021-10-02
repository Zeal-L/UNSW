p0              --关闭服务器
p1              --启动服务器
createdb test   --创建服务器
psql test       --打开服务器

create table R (x int, y int);
insert into R values (1,2), (2,3), (3,4), (5,4);
select * from R;
select * from R where x > y;

\q              --离开服务器
psql -l         --服务器列表

psql test
drop table R;
DROP TABLE  table(s)  [ CASCADE ];
TRUNCATE TABLE  table(s)  [ CASCADE ];
\q

dropdb test     --删除服务器
psql -l

pg_ctl stop

select * from Employees where hoursPweek = (select max(hoursPweek) from Employees);

pg_dump dbname > dumpfile
psql dbname -f dumpfile