for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && timeout 10m dnsenum --enum $target >> OUT-WEB-BIRD/$target/$target-dnsenum;done
