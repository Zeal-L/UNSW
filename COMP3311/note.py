import psycopg2

try:
    db = psycopg2.connect("dbname = ass1")
except Exception as e:
    print("Unable to connect to the database\n", e)

cur = db.cursor()
cur.execute("select name from Beers limit 5")

for tup in cur.fetchall():
    x = tup[0]
    print(x)


print()
cur.execute("select name from breweries limit 5")
while True:
    tup = cur.fetchone()
    if tup == None: break
    x = tup[0]
    print(x)

cur.close()
db.close()