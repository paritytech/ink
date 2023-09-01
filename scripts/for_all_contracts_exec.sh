#!/bin/bash

SCRIPT_NAME="${BASH_SOURCE[0]}"
FIND_PATH=$1
COMMAND=${@:2}

function usage {
  cat << EOF
Usage: ${SCRIPT_NAME} FIND_PATH COMMAND [INITIAL-ARGS]

Execute the supplied COMMAND with INITIAL-ARGS for all ink! contracts (recursively) found in the given path.
The manifest path (full path to the Cargo.toml file) is passed as the last argument to the supplied command.

Returns 0 (success) if the command succeeds against *all* contract projects, if any fail returns 1 (failure).

FIND_PATH
  Path to recursively find contract projects for which to execute the supplied command

EXAMPLES
   ${SCRIPT_NAME} integration-tests cargo check --manifest-path

EOF
}

if [ -z "$FIND_PATH" ] || [ -z "$COMMAND" ]; then
  usage
  exit 1
fi

# enable recursive globs
shopt -s globstar

SCRIPTS_PATH=$( cd "$(dirname "$SCRIPT_NAME")" || exit; pwd -P )
SUCCESSES=()
FAILURES=()

for manifest_path in "$FIND_PATH"/**/Cargo.toml;
  do if "$SCRIPTS_PATH"/is_contract.sh "$manifest_path"; then
    echo Running: "$COMMAND" "$manifest_path";
    $COMMAND "$manifest_path";

    if [ $? -eq 0 ]; then
      SUCCESSES+=("$manifest_path")
    else
      FAILURES+=("$manifest_path")
    fi
  fi
done

GREEN='\033[1;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

printf "\nSucceeded: %s\n" ${#SUCCESSES[@]}
for success in "${SUCCESSES[@]}"; do
  printf "  ${GREEN}\u2713${NC} %s \n" "$success"
done

printf "\nFailed: %s\n" ${#FAILURES[@]}
for failure in "${FAILURES[@]}"; do
  printf "  ${RED}\u2717${NC} %s \n" "$failure"
done

if [ ${#FAILURES[@]} -gt 0 ]; then
  exit 1
else
  exit 0
fi
