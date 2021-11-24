result1=$(python3 decorator.py CrocodileLikesStrawberries)
expected1="\['Hello', 'How', 'Are', 'You\?'\]"
[[ $result1 =~ $expected1 ]] && echo "Test passed" || (echo "Test failed"; exit 1)

python3 decorator.py Hello && {
    (echo "Test failed"; exit 1)
} || {
    echo "Test passed"
}

python3 decorator.py && {
    (echo "Test failed"; exit 1)
} || {
    echo "Test passed"
}
