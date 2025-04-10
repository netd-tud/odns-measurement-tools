# How to run
## Step 1: ZGrab2
 - Download and run zgrab2 against a target list of IP-addresses to obtain banners of interest (http [80,8080], https [443,8443], ssh ...)
 - `echo input_ips.txt | ./zgrab2 multiple -c multiple.ini -o output.json`
 - Below is an example for `multiple.ini`:
 ```
[http]
name="http80"
port=80
endpoint="/"
max-redirects=5
user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
[http]
name="http8080"
port=8080
endpoint="/"
max-redirects=5
user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
[http]
name="https443"
port=443
use-https=true
endpoint="/"
max-redirects=5
user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
[http]
name="https8443"
port=8443
use-https=true
endpoint="/"
max-redirects=5
user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
[ssh]
port=22
 ```
## Step 2: Analyze banners
 - separate all successful banners and IPs for further processing
 - `cat output.json | grep "success" > output_success.json`
 - ensure python venv is setup and all requirements downloaded, if not run: 
 - `python3 -m venv .venv && source .venv/bin/active && pip install -r requirements.txt`
 - run the regex script to obtain a list
 - `python analyze_vendors.py --mode zgrab --input output_success.json`
 
 This is a first list (`parsed_results.csv`) of vendors and router models but probably not sufficient.

## Step 3: Use Selenium
 - obtain a list of IPs from the previous output that can be accessed with selenium
 - `cat parsed_results.csv | grep "http80" | cut -d ";" -f 1 > parsed_results_ips_http80.csv`
 - run the selenium script against this list
 - `python selenium_analyze.py parsed_results_ips_http80.csv`

This will require some computing power and memory as multiple instances of Chrome will be launched in the background.
Increase or reduce the number of instances by setting `num_workers` in `selenium_analyze.py`.
The output folder `output_selenium` will contain the site's html and screenshots of each successful address.

## Step 4: Analyze selenium output
 - extract device information based on the html source
 - `python analyze_vendors.py --mode selenium --input output_selenium/ok/html`

 This will also take some time. Output is written to `parsed_results_html.csv`

## Step 5: Scan snmp
 - to improve the fingerprinting scan for snmp
 - `gcc -o onesixtyone.bin onesixtyone/onesixtyone.c`
 - `./onesixtyone.bin -i <list-of-ips> -o results_snmp.txt`
 - `python analyze_vendors.py --mode snmp --input results_snmp.txt` 

## Step 6: Combine the results
 - `python combine_results.py parsed_results.csv parsed_results_html.csv parsed_results_snmp.csv`

 The resulting `combined_results.csv` now contains both data.
 To get a quick overview of the device vendors run `cat combined_results.csv | cut -d ";" -f 3 | sort | uniq -c | sort -n`
