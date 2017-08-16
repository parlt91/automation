#!/bin/sh
set -eux

ROLE=$1
FILE=$2
SSH_CONFIG=$3
POSARGS=${4:-}
ENVIRONMENT_JSON=$FILE

test_role() {
    fqdns=$(jq -r "[.minions[] | select(.role==\"$1\") | .fqdn ] | join(\",\" )" $FILE)
    if [ -n "$fqdns" ]; then
        pytest --ssh-config=$SSH_CONFIG --connection ssh --sudo -m "$1 or common" --hosts $fqdns --junit-xml $1.xml -v $POSARGS
    fi
}

if [ "$ROLE" == "all" ]; then
    for role in "worker" "master" "admin"; do
        test_role $role
    done
else
    test_role $ROLE
fi