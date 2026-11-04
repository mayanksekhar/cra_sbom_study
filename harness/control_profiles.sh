#!/usr/bin/env bash
# Controls for Maven profile handling. No vulnerability databases needed.
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
base="$(mktemp -d /tmp/cra_profctl.XXXXXX)"

mkpom() { # $1 dir, $2 extra profile block
  mkdir -p "$1"
  cat > "$1/pom.xml" << EOF
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId><artifactId>profctl</artifactId><version>1.0</version><packaging>jar</packaging>
  <dependencies>
    <dependency><groupId>commons-codec</groupId><artifactId>commons-codec</artifactId><version>1.15</version></dependency>
  </dependencies>
  <profiles>
    <profile>
      <id>default-on</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency></dependencies>
    </profile>
$2
    <profile>
      <id>flag-only</id>
      <dependencies><dependency><groupId>commons-collections</groupId><artifactId>commons-collections</artifactId><version>3.2.2</version></dependency></dependencies>
    </profile>
  </profiles>
</project>
EOF
  python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('$1/pom.xml')" || { echo "pom in $1 is not well formed"; exit 1; }
  git -C "$1" init -q && git -C "$1" add -A && git -C "$1" -c user.email=x@y -c user.name=x commit -q -m t
}

run() { # $1 dir, $2 label
  local d="$1"
  echo "== $2"
  echo "active profiles:"; (cd "$d" && mvn -B help:active-profiles 2>&1 | grep -E '^ - ')
  (cd "$d" && mvn -B -q dependency:list -DoutputFile="$d/list.txt" > "$d/mvn.log" 2>&1) || { echo "mvn failed"; tail -n 5 "$d/mvn.log"; return; }
  echo "maven resolves:"; grep -oE '[a-z.-]+:[a-z0-9.-]+:jar:[0-9.]+' "$d/list.txt" | sort -u | sed 's/^/   /'
  syft scan "dir:$d" -o "cyclonedx-json=$d/syft.json" -q < /dev/null
  trivy fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$d/trivy.json" -q "$d" < /dev/null
  (cd "$root/tools" && npx cdxgen --spec-version 1.6 -t java -o "$d/cdxgen.json" "$d" < /dev/null > "$d/cdxgen.log" 2>&1)
  printf '%-8s %-15s %-15s %-15s %-15s\n' tool "plain" "default-on" "jdk-on" "flag-only"
  for t in syft trivy cdxgen; do
    printf '%-8s' "$t"
    for a in commons-codec commons-lang3 commons-io commons-collections; do
      printf ' %-15s' "$([ -f "$d/$t.json" ] && jq -r "[.components[]? | select(.name==\"$a\") | .version] | join(\",\")" "$d/$t.json" || echo NOFILE)"
    done; echo
  done
}

jdk='    <profile><id>jdk-on</id><activation><jdk>[11,)</jdk></activation><dependencies><dependency><groupId>commons-io</groupId><artifactId>commons-io</artifactId><version>2.11.0</version></dependency></dependencies></profile>'
mkpom "$base/with_jdk_profile" "$jdk"
mkpom "$base/without_jdk_profile" ""
run "$base/with_jdk_profile" "control 1: plain, activeByDefault, JDK 11+ profile, flag only (a JDK profile deactivates activeByDefault)"
run "$base/without_jdk_profile" "control 2: plain, activeByDefault, flag only (activeByDefault stays active)"
echo "(columns: plain dependency, activeByDefault profile, JDK 11+ profile, profile needing -P). Work dir: $base"
