import psycopg2
zid = 5128688
q1 = '''
select t.id,t.code
from   program_enrolments e
       join terms t on e.term = t.id
where  e.student = %s
order by t.starting
'''
q2 = '''
select s.code, s.name
from   course_enrolments e
       join courses c on e.course = c.id
       join subjects s on c.subject = s.id
where  c.term = %s and e.student = %s
order by s.code
'''

try:
    db = psycopg2.connect("dbname=mymyunsw")
    c1 = db.cursor()
    c2 = db.cursor()
    c1.execute(q1, [zid])
    for t in c1.fetchall():
        print(t[1])
        c2.execute(q2, [t[0], zid])
        for s in c2.fetchall():
            print(s[0], s[1])
    c2.close()
    c1.close()
except:
    print("DB error: ", err)
finally:
    if db:
        db.close()
