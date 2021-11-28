-- COMP3311 20T3 Final Exam
-- Q1: view of teams and #matches

-- ... helper views (if any) go here ...

create or replace view Q1(team,nmatches)
as
select t.country, count(*) as nmatches
from teams t
join involves inv on inv.team = t.id
group by t.country
order by t.country;


