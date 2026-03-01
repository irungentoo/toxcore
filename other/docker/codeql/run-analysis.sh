#!/bin/bash
set -e
echo "Creating CodeQL Database..."
codeql database create codeql-db --language=cpp --overwrite --command="./build.sh"
echo "Analyzing..."
codeql database analyze codeql-db codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls --format=csv --output=codeql-db/results.csv
echo "Analysis complete. Results in codeql-db/results.csv"
cat codeql-db/results.csv
