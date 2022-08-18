#! /bin/dash

exitcode=0

for i in "$@"; do
    if [ "$(echo "$i" | grep -Ec '\.')" = 1 ]; then
        echo "# $i already has an extension"
        exitcode=1
    elif [ "$(sed -n -e '1p' < "$i" | grep -Ec '^\#\!')" = 0 ]; then
        echo "# $i does not have a #! line"
        exitcode=1
    elif [ "$(sed -n -e '1p' < "$i" | grep -Ec 'perl|python|sh')" = 0 ]; then
        echo "# $i no extension for #! line"
        exitcode=1
    elif [ "$(sed -n -e '1p' < "$i" | grep -Ec 'python')" = 1 ]; then
        if [ -f "$i.py" ]; then
            echo "# $i.py already exists"
            exitcode=1
        else
            echo "mv $i $i.py"
        fi
    elif [ "$(sed -n -e '1p' < "$i" | grep -Ec 'perl')" = 1 ]; then
        if [ -f "$i.pl" ]; then
            echo "# $i.pl already exists"
            exitcode=1
        else
            echo "mv $i $i.pl"
        fi
    elif [ "$(sed -n -e '1p' < "$i" | grep -Ec 'sh')" = 1 ]; then
        if [ -f "$i.sh" ]; then
            echo "# $i.sh already exists"
            exitcode=1
        else
            echo "mv $i $i.sh"
        fi
    fi
done

exit $exitcode



