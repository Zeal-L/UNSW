#! /bin/dash


for i in "$@"
do
    echo "$i" 'displayed to screen if possible'
    display "$i" 2>/dev/null
    echo -n 'Address to e-mail this image to? '
    read -r email
    if [ "$email" = "" ]
    then
        echo "No email sent" 1>&2
        exit 1
    fi
    echo -n 'Message to accompany image? '
    read -r message
    mutt -s "$message" -e 'set copy=no' -a "$i" -- "$email"
    echo "$i" 'sent to' "$email"
done