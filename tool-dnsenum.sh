for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && dnsenum -enum -w $target >> OUT-WEB-BIRD/$target/$target-dnsenum && ./tool-amass.sh ;done
