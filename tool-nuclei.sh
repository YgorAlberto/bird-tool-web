mkdir -p OUT-WEB-BIRD/$1
nuclei -H "Mozilla/5.0" -u "http://"$1 >> OUT-WEB-BIRD/$1/$1-nuclei
nuclei -H "Mozilla/5.0" -u "https://"$1 >> OUT-WEB-BIRD/$1/$1-s-nuclei
