for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && amass enum -d $target >> OUT-WEB-BIRD/$target/$target-amass && ./tool-dnsrecon.sh ;done
