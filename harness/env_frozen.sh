root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SNAP="$root/vulndb/20261026"
export GRYPE_DB_CACHE_DIR="$SNAP/grype"
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_VALIDATE_AGE=false
export GRYPE_CHECK_FOR_APP_UPDATE=false
