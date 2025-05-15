mkdir -p OUT-WEB-BIRD/$1
wapiti --scope domain -m all -d 10 -A Mozilla/5.0 -u "https://$1" >> OUT-WEB-BIRD/$1/$1-wapiti
wapiti --scope domain -m all -d 10 -A Mozilla/5.0 -u "http://$1" >> OUT-WEB-BIRD/$1/$1-s-wapiti
