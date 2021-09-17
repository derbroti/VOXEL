#!/bin/bash

find net -type f -print | xargs -i rm chrome/src/{}
find net -type f -print0 | while IFS= read -r -d '' file; do depth=$(echo "$file" | grep -o '/' | wc -l); depth=$((depth+2));rep=$(yes "../" | head -n $depth | tr -d '\n'); ln -s "$rep""$file" chrome/src/"$file"; done
