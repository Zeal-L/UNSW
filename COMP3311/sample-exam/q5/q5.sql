-- COMP3311 20T3 Final Exam
-- Q5: show "cards" awarded against a given team

-- ... helper views and/or functions go here ...

drop function if exists q5(text);
drop type if exists RedYellow;

create type RedYellow as (nreds integer, nyellows integer);

create or replace function
	Q5(_team text) returns RedYellow
as $$
declare
	result RedYellow;
begin
	perform * from Teams where country = _team;
    if (not found) then result := (NULL, NULL); return result; end if;

	SELECT COUNT(*) INTO result.nreds FROM Players p
		JOIN Cards c on c.givento = p.id
		JOIN Teams t on t.id = p.memberof
		where t.country = _team and c.cardtype = 'red';
	SELECT COUNT(*) INTO result.nyellows FROM Players p
		JOIN Cards c on c.givento = p.id
		JOIN Teams t on t.id = p.memberof
		where t.country = _team and c.cardtype = 'yellow';
	return result;
end;
$$ language plpgsql
;
