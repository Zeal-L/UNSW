-- COMP3311 21T3 Assignment 1
--
-- Fill in the gaps ("...") below with your code
-- You can add any auxiliary views/function that you like
-- The code in this file MUST load into a database in one pass
-- It will be tested as follows:
-- createdb test; psql test -f ass1.dump; psql test -f ass1.sql
-- Make sure it can load without errorunder these conditions
-- Q1: oldest brewery
CREATE
OR replace VIEW Q1(brewery) AS
SELECT
	NAME AS brewery
FROM
	breweries
WHERE
	founded = (
		SELECT
			MIN(founded)
		FROM
			breweries
	);

-- Q2: collaboration beers
CREATE
OR replace VIEW Q2(beer) AS
SELECT
	beers.name AS beer -- er1.name AS brewery,
	-- er2.name AS brewery
FROM
	brewed_by b1
	JOIN brewed_by b2 ON b1.beer = b2.beer
	JOIN beers ON beers.id = b1.beer -- JOIN breweries er1 ON er1.id = b1.brewery
	-- JOIN breweries er2 ON er2.id = b2.brewery
WHERE
	b1.brewery != b2.brewery
	AND b1.brewery < b2.brewery;

-- Q3: worst beer
CREATE
OR replace VIEW Q3(worst) AS
SELECT
	NAME AS worst
FROM
	beers
WHERE
	rating = (
		SELECT
			MIN(rating)
		FROM
			beers
	);

-- Q4: too strong beer
CREATE
OR replace VIEW Q4(beer, abv, STYLE, max_abv)
) AS
SELECT
	b.name AS beer,
	b.abv,
	s.name AS STYLE,
	s.max_abv
FROM
	beers b
	JOIN styles s ON b.style = s.id
WHERE
	b.abv > s.max_abv;

-- Q5: most common style
CREATE
OR replace VIEW Q5(STYLE) AS
SELECT
	s.name AS STYLE
FROM
	styles s
	JOIN beers b ON b.style = s.id
GROUP BY
	s.name
ORDER BY
	COUNT(*) DESC
LIMIT
	1;

-- Q6: duplicated style names
CREATE
OR replace VIEW Q6(style1, style2) AS
SELECT
	s1.name AS style1,
	s2.name AS style2
FROM
	styles s1
	JOIN styles s2 ON s1.name ilike s2.name
WHERE
	s1.name > s2.name;

-- Q7: breweries that make no beers
CREATE
OR replace VIEW Q7(brewery) AS
SELECT
	er.name AS brewery
FROM
	breweries er
	LEFT OUTER JOIN brewed_by b ON b.brewery = er.id
WHERE
	b.brewery IS NULL;

-- Q8: city with the most breweries
CREATE
OR replace VIEW Q8(city, country) AS
SELECT
	l.metro AS city,
	l.country
FROM
	locations l
	JOIN breweries er ON l.id = er.located_in
	AND l.metro IS NOT NULL
GROUP BY
	l.metro,
	l.country
ORDER BY
	COUNT(*) DESC
LIMIT
	1;

-- Q9: breweries that make more than 5 styles
CREATE
OR replace VIEW Q9(brewery, nstyles) AS
SELECT
	er.name AS brewery,
	COUNT(DISTINCT b.style) AS nstyles
FROM
	breweries er
	JOIN brewed_by r ON er.id = r.brewery
	JOIN beers b ON b.id = r.beer
GROUP BY
	er.name
HAVING
	(COUNT(DISTINCT(b.style)) > 5)
ORDER BY
	er.name ASC;

-- Q10: beers of a certain style
CREATE
OR replace VIEW BeerInfo(beer, brewery, STYLE, YEAR, abv) AS
SELECT
	b.name AS beer,
	er.name AS brewery,
	s.name AS STYLE,
	b.brewed AS YEAR,
	b.abv
FROM
	beers b
	JOIN brewed_by bb ON b.id = bb.beer
	JOIN breweries er ON er.id = bb.brewery
	JOIN styles s ON s.id = b.style;

CREATE
OR replace FUNCTION q10(_style text) returns setof BeerInfo AS $$
SELECT
	*
FROM
	BeerInfo
WHERE
	_style = STYLE $$ LANGUAGE SQL;

-- Q11: beers with names matching a pattern
CREATE
OR replace FUNCTION Q11(partial_name text) returns setof text AS $$
DECLARE
result text;
begin



$$ LANGUAGE plpgsql;

-- Q12: breweries and the beers they make
CREATE
OR replace FUNCTION Q12(partial_name text) returns setof text AS $$ ... $$ LANGUAGE plpgsql;