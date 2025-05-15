#!/bin/bash
cd OUT-WEB-BIRD/
grep -riah ".$1" | grep -v "grep" | grep -v "Trying" | grep -v "Scraping" | grep -v "\-\-\-" |grep -v "IN" | cut -d " " -f 1 | grep -via "\.arpa" |sort -u > ../subdomains-full.txt

