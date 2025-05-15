mkdir -p OUT-WEB-BIRD/$1
sublist3r -n -d $1 | grep "$1" | grep -v "Enumerating" >> OUT-WEB-BIRD/$1/$1-sublist3r
