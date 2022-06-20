#!/bin/sh -eu

DEBUG=${DEBUG:-"0"}

if [ "${DEBUG}" = "1" ]; then
    set -x
fi

export PATH=/usr/local/bin:/usr/sbin:/sbin:${PATH}

#
# Main
#

# if command starts with an option, prepend mws
if [ "${1:0:1}" = '-' ]; then
     set -- mws "$@"
fi

exec "$@"
