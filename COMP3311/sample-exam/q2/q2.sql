-- COMP3311 20T3 Final Exam
-- Q2: view of amazing goal scorers

-- ... helpers go here ...
-- Write an SQL view that gives the names of all players who have scored more than one goal that is rated as "amazing".
-- Each tuple in the result should also include the number of amazing goals scored.
create or replace view Q2(player,ngoals)
as
select p.name as player, count(g.scoredin) as ngoals
from players p
join goals g on p.id = g.scoredby
where g.rating = 'amazing'
group by p.name
having count(g.scoredin) > 1
order by p.name;


