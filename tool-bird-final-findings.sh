#!/bin/bash
for target in $(cat target.txt);do if [ -s OUT-WEB-BIRD/$target/$target-FULL-URLs ];then python3 bird-final-findings.py -f OUT-WEB-BIRD/$target/$target-FULL-URLs --json-output OUT-WEB-BIRD/$target/$target-bird-final-findings.json --scope-domain "${BIRD_SCOPE_DOMAIN:-$target}" --workers 8 --timeout 8 --connect-timeout 4;fi;done
