JUNIT="lib/junit-platform-console-standalone-1.7.0-M1.jar"
JSONASSERT="lib/jsonassert-1.2.3.jar"
JSON="lib/json.jar"

function run_junit() {
    exercise=$1
    rm -rf bin
    javac -d bin -cp "$JUNIT:$JSONASSERT:$JSON" $(find src/$exercise -name "*.java")
    java -jar "$JUNIT" -cp "$JSONASSERT:$JSON:bin:src/$exercise" --scan-class-path --disable-ansi-colors --disable-banner 2>&1
}


# Hotel
run_junit hotel

# Piazza
# run_junit unsw