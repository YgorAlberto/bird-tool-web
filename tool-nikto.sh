mkdir -p OUT-WEB-BIRD/$1
nikto -useragent Mozilla/5.0 -host "https://$1" >> OUT-WEB-BIRD/$1/$1-nikto
nikto -useragent Mozilla/5.0 -host "http://$1" >> OUT-WEB-BIRD/$1/$1-s-nikto
