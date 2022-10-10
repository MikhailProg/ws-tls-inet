#/bin/sh

set -eu

trap 'rm -f log.$$' EXIT

PATH=$PATH:.

command -v rdwr || { echo >&2 'error: build the project'; exit 1; }

 : ${GB:=2}

perf() {
    wsopt="-h test -u /"
    cnt="count=$((GB*1024))"
    blk="bs=1M"

    # Pass data from a server to a client, use different combinations.
    # dd consumes data and measures speed.
    while read line; do
        txt=${line%@*}
        cmd=${line#*@}
        dd $blk $cnt if=/dev/zero status=noxfer 2>/dev/null | \
            $cmd -- dd $blk of=/dev/null 2>log.$$
        sleep 2
        speed=$(sed -n 's/^.* s, //p' log.$$)
        printf "%15s %15s\n" $txt "$speed"
    done <<EOF
RDWR        @rdwr            -- rdwr   -- rdwr   -- rdwr
WS(txt)     @ws $wsopt -s    -- rdwr   -- rdwr   -- ws $wsopt -r
WS(bin)     @ws $wsopt -s -b -- rdwr   -- rdwr   -- ws $wsopt -r -b
TLS         @rdwr            -- tls -s -- tls -r -- rdwr
WS(txt)+TLS @ws $wsopt -s    -- tls -s -- tls -r -- ws $wsopt -r
WS(bin)+TLS @ws $wsopt -s -b -- tls -s -- tls -r -- ws $wsopt -r -b
EOF
    unset wsopt blk cnt speed line cmd txt
}

perf

