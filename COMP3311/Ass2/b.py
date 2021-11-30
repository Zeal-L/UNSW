import psycopg2
zid = 5128688
q1 = '''
select t.id, t.code, s.code, s.name
from   course_enrolments e
       join courses c on e.course = c.id
       join terms t on c.term = t.id
       join subjects s on c.subject = s.id
where  e.student = %s
order by t.starting,s.code
'''

try:
    db = psycopg2.connect("dbname=mymyunsw")
    c = db.cursor()
    c.execute(q1, [zid])
    prev = 0
    for t in c.fetchall():
        if t[1] != prev:
            print(t[1])
        print(t[2], t[3])
        prev = t[1]
    c.close()
except:
    print("DB error: ", err)
finally:
    if db:
        db.close()
