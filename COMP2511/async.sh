#! /bin/dash

trap 'echo loop expected $n times in 1 second; exit 0' TERM

my_process_id=$$
(sleep 1; kill $my_process_id) &

n=0
while true; do
    n=$((n+1))
done