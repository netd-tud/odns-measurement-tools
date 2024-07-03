#!/bin/bash

if [ -z "$1" ]; then
    echo "Filename missing"
    exit 1
fi

filename=$1

echo "total entries:"
zcat $filename | wc -l

echo "control record present:"
zcat $filename | awk -F';' '{split($4, a, ","); for (i in a) if (a[i] == "91.216.216.216" && length(a)==2) {print; break}}' | wc -l

echo "recursive resolver:"
zcat $filename | awk -F';' '$2 == $3 {split($4, a, ","); matchFound = 0; ctrlPresent = 0; for (i in a) { if (a[i] == $3) matchFound = 1; if (a[i] == "91.216.216.216") ctrlPresent = 1;} if (length(a)==2 && matchFound && ctrlPresent) print}' | wc -l

echo "recursive fwds:"
zcat $filename | awk -F';' '$2 == $3 {split($4, a, ","); matchFound = 0; ctrlPresent = 0; for (i in a) { if (a[i] == $3) matchFound = 1; if (a[i] == "91.216.216.216") ctrlPresent = 1;} if (length(a)==2 && !matchFound && ctrlPresent) print}' | wc -l

echo "transparent fwds:"
zcat $filename | awk -F';' '$2 != $3 {split($4, a, ","); for (i in a) if (a[i] == "91.216.216.216" && length(a)==2) {print; break}}' | wc -l
