-- COMP3311 21T3 Ass2 ... extra database definitions
-- add any views or functions you need into this file
-- note: it must load without error into a freshly created mymyunsw database
-- you must submit this even if you add nothing to it

-- Q1
CREATE
OR replace VIEW Q1_course
(Student, CourseCode, Term, CourseTitle, Mark, Grade, UOC) AS
SELECT
    s.id AS Student,
	sub.code AS CourseCode,
	t.code AS Term,
	sub.name AS CourseTitle,
	c_en.mark AS Mark,
	c_en.grade AS Grade,
    sub.uoc AS UOC
FROM
    students s
    JOIN course_enrolments c_en ON c_en.student = s.id
	JOIN courses c ON c.id = c_en.course
    JOIN subjects sub ON sub.id = c.subject
    JOIN terms t ON t.id = c.term
ORDER BY t.code, sub.code;


CREATE
OR replace FUNCTION Q1_trans(zid integer) returns setof TranscriptRecord AS $$
DECLARE
	v1 RECORD;
	reselt TranscriptRecord;
BEGIN
	FOR v1 IN
        SELECT
			*
		FROM
			Q1_course
		WHERE
			Student = zid
	LOOP
        reselt.code  := v1.CourseCode;
        reselt.term  := v1.Term;
        reselt.name  := v1.CourseTitle;
        reselt.mark  := v1.Mark;
        reselt.grade := v1.Grade;
        reselt.uoc   := v1.UOC;
        RETURN next reselt;
	END LOOP;
END;
$$ LANGUAGE plpgsql;


-- Q2
CREATE
OR replace VIEW Q2_program_info
(programCode, programName, uoc, duration, info) AS
SELECT
    p.id AS programCode,
    p.name AS programName,
    p.uoc AS uoc,
    p.duration AS duration,
    o.longname AS info
FROM
    programs p
    JOIN orgunits o ON o.id = p.offeredby
;

CREATE
OR replace VIEW Q2_streams_courses
(programCode, min_req, gtype, gname, gdefby, definition) AS
SELECT
    p_r.program AS programCode,
    r.min_req AS min_req,
    aog.type AS gtype,
    r.name AS gname,
    aog.defby AS gdefby,
    aog.definition AS definition
FROM
    program_rules p_r
    JOIN rules r ON r.id = p_r.rule
    JOIN academic_object_groups aog ON aog.id = r.ao_group
;

CREATE
OR replace VIEW Q2_streams_rule
(streamCode, rname, min_req, max_req, gdefby, definition) AS
SELECT
    s.code AS streamCode,
    r.name AS rname,
    r.min_req AS min_req,
    r.max_req AS max_req,
    aog.defby AS gdefby,
    aog.definition AS definition
FROM
    streams s
    JOIN stream_rules s_r ON s_r.stream = s.id
    JOIN rules r ON r.id = s_r.rule
    JOIN academic_object_groups aog ON aog.id = r.ao_group
;

select s.code, s.name, c_e.student, t.code, c_e.mark, c_e.grade, s.uoc, c.id
                            from subjects s
                            JOIN courses c ON c.subject = s.id
                            JOIN course_enrolments c_e ON c_e.course = c.id
                            JOIN terms t ON t.id = c.term
                            where c_e.student = 5198386;