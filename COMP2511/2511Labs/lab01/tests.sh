#!/bin/bash
function run_junit() {
    exercise=$1
    rm -rf bin/$exercise
    javac -d bin -cp "$JUNIT" $(find src/$exercise -name "*.java")
    java -jar "$JUNIT" -cp bin:src/$exercise --scan-class-path --disable-ansi-colors --disable-banner 2>&1
}

cd src
# Average
javac average/Average.java || exit 1
diff <(java average/Average) <(echo "The average is 3.5") || exit 1

# Splitter 
javac splitter/Splitter.java || exit 1
diff <(java splitter/Splitter <<< "Welcome to my humble abode") <(printf "Enter a message: \nWelcome\nto\nmy\nhumble\nabode\n") || exit 1

# Satellite
javac satellite/Satellite.java || exit 1
diff <(java satellite/Satellite) <(printf "I am Satellite A at position 122.0 degrees, 10000 km above the centre of the earth and moving at a velocity of 55.0 metres per second\n2.129301687433082\n0.04303052592865024\n4380.0\n") || exit 1

cd ..

JUNIT="lib/junit-platform-console-standalone-1.7.0-M1.jar"

# Piazza
run_junit unsw

# Scrabble
# run_junit scrabble
