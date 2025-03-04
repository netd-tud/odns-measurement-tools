#!/bin/bash
set -e

CONFIG_FILE=scanner/udp/config_uniq.yml
TEMP_UNIQ_RESOLVERS_PATH=_uniq_resolvers.csv

input_file="udp_results.csv.gz"
if [ -n "$1" ]; then
    input_file=$1
fi

if [ ! -f $input_file ]; then
    echo "input file $input_file not present"
    exit 1
fi

scan_output_file="uniq_resolver_responses.csv.gz"
if [ -n "$2" ]; then
    scan_output_file=$2
fi

intersect_out=intersect_out.csv.gz
if [ -n "$3" ]; then
    intersect_out=$3
fi

echo "accumulating unique resolvers"
zcat $input_file | grep ";Transparent" | cut -d ";" -f 3 | tail -n +2 | sort | uniq | shuf > $TEMP_UNIQ_RESOLVERS_PATH
echo "there are $(cat $TEMP_UNIQ_RESOLVERS_PATH | wc -l) unique resolvers"

if [ ! -f  $CONFIG_FILE ]; then
    echo "config file $CONFIG_FILE not present"
    exit 1
fi

echo "checking which unique resolvers are public"
sudo go run dns_tool.go -m s -p udp -c $CONFIG_FILE -o $scan_output_file $TEMP_UNIQ_RESOLVERS_PATH
sudo rm $TEMP_UNIQ_RESOLVERS_PATH
echo "there are $(cat $scan_output_file | wc -l) public resolvers"

echo "determining negated intersection of public and restrictive resolvers"
source .venv/bin/activate
python ratelimit/intersect.py $scan_output_file $input_file $intersect_out

echo "starting ratelimit testing"
sudo go run dns_tool.go -m r -v 5 -c ratelimit/config.yml $intersect_out