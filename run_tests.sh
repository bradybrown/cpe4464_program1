#!/usr/bin/env bash

TEST_DIR="CPE4464_p1_files"
PROGRAM="./trace-Linux-x86_64"
status=0

for expected in "$TEST_DIR"/*.out.txt; do
    test_name="${expected%.out.txt}"
    pcap_file="${test_name}.pcap"

    if [[ ! -f "$pcap_file" ]]; then
        echo "SKIP: Missing $pcap_file"
        status=1
        continue
    fi

    echo "Testing $(basename "$test_name")..."

    if diff --color=auto -u "$expected" <("$PROGRAM" "$pcap_file"); then
        echo "PASS"
    else
        echo "FAIL"
        status=1
    fi

    echo
done

exit "$status"
