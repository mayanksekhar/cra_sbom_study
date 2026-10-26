#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
gt="$root/groundtruth/maven"; mkdir -p "$gt"
mvn -version > "$gt/_tooling.txt" 2>&1
conv() {
  awk -F: 'NF>=5 { gsub(/^ +/,"",$1);
    if (NF==5) print "pkg:maven/"$1"/"$2"@"$4;
    else if (NF==6) print "pkg:maven/"$1"/"$2"@"$5;
    else print "pkg:maven/"$1"/"$2"@"$(NF-1) }' | sort -u
}
for name in spring_petclinic commons_text; do
  cd "$root/dataset/src/$name"
  g=$(mvn -B -q help:evaluate -Dexpression=project.groupId -DforceStdout)
  a=$(mvn -B -q help:evaluate -Dexpression=project.artifactId -DforceStdout)
  echo "$g/$a" | tr 'A-Z' 'a-z' > "$gt/${name}_mainmodule.txt"
  mvn -B -q dependency:list -Dsort=true -DoutputFile=/tmp/${name}_all.txt
  mvn -B -q dependency:list -Dsort=true -DincludeScope=runtime -DoutputFile=/tmp/${name}_shipped.txt
  conv < /tmp/${name}_all.txt > "$gt/${name}_all.txt"
  conv < /tmp/${name}_shipped.txt > "$gt/${name}_shipped.txt"
  date -u +%Y%m%dT%H%M%SZ > "$gt/${name}_resolved_at.txt"
done
wc -l "$gt"/*_all.txt "$gt"/*_shipped.txt; cat "$gt"/*_mainmodule.txt
