-- COMP3311 20T3 Final Exam
-- Q3: team(s) with most players who have never scored a goal

... helpers go here ...

create or replace view Q3(team,nplayers)
as
select t.country as team, count(distinct p.name) as nplayers
from teams t
join players p on p.memberof = t.id
where (SELECT count(*) FROM goals g WHERE g.scoredby = p.id) = 0
group by t.country
order by nplayers desc
limit 1
;

