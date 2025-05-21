for target in $(cat target.txt);do mkdir -p OUT-WEB-BIRD/$target && dnsrecon -d $target >> OUT-WEB-BIRD/$target/$target-dnsrecon && ./tool-fierce.sh ;done
