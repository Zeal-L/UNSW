#!/bin/bash
tests=(
    "create fluffy\nwait\nfeed fluffy\nplay fluffy\n\n"
    "create fluffball\ncreate fluffball\nwait\nwait\nwait\nwait\nwait\nwait\ncreate fluffball\n\n"
    "feed buckbeak\ncreate buckbeak\ncreate norbert\ncreate aragog\nfeed buckbeak\nfeed norbert\nfeed aragog\nplay buckbeak\nfeed buckbeak\nfeed buckbeak\nfeed aragog\nplay aragog\nfeed buckbeak\nfeed aragog\nfeed buckbeak\nplay aragog\nfeed buckbeak\nplay aragog\nwait\n\n"
)

for ((i = 0; i < ${#tests[@]}; i++)); do
    echo -e ${tests[$i]} | python3 game.py > tests/out$i.txt
    diff tests/expected$i.txt tests/out$i.txt
done
