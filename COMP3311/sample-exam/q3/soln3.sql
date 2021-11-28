drop view if exists PlayersAndGoals;
create view PlayersAndGoals
as
select p.name as player, t.country as team, count(g.id) as goals
from   Teams t
        join Players p on (p.memberof = t.id)
        left outer join Goals g on (p.id = g.scoredby)
group  by p.name, t.country ;

drop view if exists CountryAndGoalless;
create view CountryAndGoalless
as
select team, count(*) as players
from   PlayersAndGoals
where  goals = 0
group  by team ;

drop view if exists Q3;
create view Q3
as
select team, players
from   CountryAndGoalless
where  players = (select max(players) from CountryAndGoalless) ;

