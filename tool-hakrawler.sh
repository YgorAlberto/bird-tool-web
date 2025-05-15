mkdir -p OUT-WEB-BIRD/$1
echo 'http://'$1 | hakrawler | sort -u >> OUT-WEB-BIRD/$1/$1-hakrawler
echo 'https://'$1 | hakrawler | sort -u >> OUT-WEB-BIRD/$1/$1-s-hakrawler
