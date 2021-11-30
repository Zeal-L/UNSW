-- COMP3311 21T3 Exam Q4
-- Return address for a property, given its ID
-- Format: [UnitNum/]StreetNum StreetName StreetType, Suburb Postode
-- If property ID is not in the database, return 'No such property'

create or replace function address(propID integer) returns text
as
$$
declare
	result text;
	v1 record;
begin
	select p.ptype, p.unit_no, p.street_no, s.name,
		s.stype, su.name as subname, su.postcode into v1
	from properties p
	join streets s on p.street = s.id
	join suburbs su on s.suburb = su.id
	where p.id = propID;
	if (not found) then
		result := 'No such property';
	elsif (v1.ptype = 'Apartment') then
		result := v1.unit_no || '/' || v1.street_no || ' ' || v1.name
				|| ' ' || v1.stype || ', ' || v1.subname || ' ' || v1.postcode;
	elsif (v1.ptype = 'House' or v1.ptype = 'Townhouse') then
		result := v1.street_no || ' ' || v1.name || ' ' || v1.stype
				|| ', ' || v1.subname || ' ' || v1.postcode;
	end if;

	return result;
end;
$$ language plpgsql;
