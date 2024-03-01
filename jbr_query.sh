# python theHarvester.py -b linkedin -d target -l 700 -f /tmp/names && cat /tmp/names.json | jq '.linkedin_people[]' > /tmp/names
# sed -i 's/"\|[0-9]//g' /tmp/names
# sed -i 's/- .*//g' /tmp/names
# sed -i 's/ *$//g' /tmp/names
# sed -i 's/[.]//g' /tmp/names
# sed -i '/^.\{1,18\}$/d' /tmp/names # removing small names
# sed -i 's/ /%/g' /tmp/names
# sed -i 's/$/%/g' /tmp/names
# cat /tmp/names | tr '[:upper:]' '[:lower:]' | sort -u > /tmp/names.ok


jbr="$1"
linesTotal=$(wc -l $2 | cut -d' ' -f1)
counter=0
while read line; do
    ((counter++))
    echo $((100*counter/linesTotal))% >&2
    sqlite3 "$jbr" "SELECT * FROM pf WHERE nome LIKE \"$line\" LIMIT 50;" >> $3  
done < $2