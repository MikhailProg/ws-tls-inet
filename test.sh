#/bin/sh

set -eu

trap 'rm -f /tmp/check.$$ /tmp/file.$$' EXIT

PATH=$PATH:.

command -v rdwr > /dev/null || { echo >&2 'error: build the project'; exit 1; }

check() {
    COUNT="1 5 10"
    wsopt="-h test -u /"
    for unit in c K M; do
        for count in $COUNT; do
            dd if=/dev/zero of=/tmp/file.$$ bs=1$unit count=$count 2>/dev/null

            u=$unit
            if [ "$u" = c ]; then
                u=b
            fi
            # Test all transports at once.
            # Passing count bytes through forward and backward paths.
            printf "ReadWrite %3d$u: " $count
            rdwr -- ws $wsopt -- tls -- tls -s -r -- ws $wsopt -s -r -- cat < \
                        /tmp/file.$$ >/tmp/check.$$ 2>/dev/null

            cmp -s /tmp/check.$$ /tmp/file.$$ && echo PASS || echo FAIL
            rm /tmp/check.$$ /tmp/file.$$
        done
    done
    unset wsopt u unit count COUNT
}

check

