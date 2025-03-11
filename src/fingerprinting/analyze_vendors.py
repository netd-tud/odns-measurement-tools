import json
import csv
import re
import sys
import os
from tqdm import tqdm
import argparse
from common import hash_string

"""
This script analyzes router vendors and models with regex patterns.
The collection of below rules will be in no way complete nor match correctly in all cases.

To get a quick overview of the vendors and models run:
list of vendors:
$ cat combined_results.csv | cut -d ";" -f 3 | sort | uniq -c | sort -n
list of models:
$ cat combined_results.csv | cut -d ";" -f 4 | sort | uniq -c | sort -n
"""

parser = argparse.ArgumentParser(description="Analyze output files with regex for vendor/firmware")

# output csv format
headers = [
    "ip", 
    "network-operator", 
    "router-vendor", 
    "model-version", 
    "firmware-version", 
    "successful-protocols",
    "banner-hash"
]

vendor_patterns = {
    # Router Vendors
    "3Com": r"(?:^|\s|>)(3com)(?:\s|$|<)",
    "Actiontec": r"(?:^|\s|>)(actiontec)(?:\s|$|<)",
    "ADTRAN": r"(?:^|\s|>)(adtran)(?:\s|$|<)",
    "Alcatel-Lucent": r"(?:^|\s|>)(alcatel(?:\s|-)?lucent)(?:\s|$|<)",
    "Arcadyan": r"(?:^|\s|>)(arcadyan)(?:\s|$|<)",
    "Arris": r"(?:^|\s|>)(arris)(?:\s|$|<)",
    "Aruba": r"(?:^|\s|>)(aruba)(?:\s|$|<)",
    "Askey": r"(?:^|\s|>)(askey)(?:\s|$|<)",
    "Asus": r"(?:^|\s|>)(asus)(?:\s|$|<)",
    "AVM": r"(?:^|\s|>)(avm|fritz[\s-]?box)(?:\s|$|<)",
    "Billion": r"(?:^|\s|>)(billion)(?:\s|$|<)",
    "Calix": r"(?:^|\s|>)(calix)(?:\s|$|<)",
    "Ciena": r"(?:^|\s|>)(ciena)(?:\s|$|<)",
    "Cisco": r"(?:^|\s|>)(cisco|ios[\s-]?xr|ios[\s-]?xe)(?:\s|$|<)",
    "D-Link": r"(?:^|\s|>)(d[_-]?link|dlink)(?:\s|$|<)",
    "DrayTek": r"(?:^|\s|>)(draytek)(?:\s|$|<)",
    "EdgeCore": r"(?:^|\s|>)(edgecore)(?:\s|$|<)",
    "Fortinet": r"(?:^|\s|>)(fortinet|fortigate)(?:\s|$|<)",
    "Huawei": r"(?:^|\s|>)(huawei)(?:\s|$|<)",
    "Juniper": r"(?:^|\s|>)(juniper|junos)(?:\s|$|<)",
    "Linksys": r"(?:^|\s|>)(linksys)(?:\s|$|<)",
    "Mikrotik": r"(?:^|\s|>)(mikrotik|routeros)(?:\s|$|<)",
    "Motorola": r"(?:^|\s|>)(motorola)(?:\s|$|<)",
    "Netgear": r"(?:^|\s|>)(netgear)(?:\s|$|<)",
    "OpenWrt": r"(?:^|\s|>)(openwrt)(?:\s|$|<)",
    "Pace": r"(?:^|\s|>)(pace)(?:\s|$|<)",
    "Ruckus": r"(?:^|\s|>)(ruckus)(?:\s|$|<)",
    "Sagemcom": r"(?:^|\s|>)(sagemcom)(?:\s|$|<)",
    "Siemens": r"(?:^|\s|>)(siemens)(?:\s|$|<)",
    "Technicolor": r"(?:^|\s|>)(technicolor)(?:\s|$|<)",
    "Tenda": r"(?:^|\s|>)(tenda)(?:\s|$|<)",
    "TP-Link": r"(?:^|\s|>)(tp[\s-]?link)(?:\s|$|<)",
    "Ubiquiti": r"(?:^|\s|>)(ubiquiti|edgeos|unifi)(?:\s|$|<)",
    "ZTE": r"(?:^|\s|>)(zte)(?:\s|$|<)",
    "Zyxel": r"(?:^|\s|>)(zyxel)(?:\s|$|<)",
    
    # NAS Vendors
    "Synology": r"(?:^|\s|>)(synology)(?:\s|$|<)",
    "QNAP": r"(?:^|\s|>)(qnap)(?:\s|$|<)",
    "Asustor": r"(?:^|\s|>)(asustor)(?:\s|$|<)",
    "Thecus": r"(?:^|\s|>)(thecus)(?:\s|$|<)",
    "Buffalo": r"(?:^|\s|>)(buffalo)(?:\s|$|<)",
    "Western Digital": r"(?:^|\s|>)(western\s*digital|wd)(?:\s|$|<)",
    
    # Smart IoT Devices / Appliances
    "Samsung": r"(?:^|\s|>)(samsung)(?:\s|$|<)",
    "LG": r"(?:^|\s|>)(lg)(?:\s|$|<)",
    "Bosch": r"(?:^|\s|>)(bosch)(?:\s|$|<)",
    "Whirlpool": r"(?:^|\s|>)(whirlpool)(?:\s|$|<)",
    "GE Appliances": r"(?:^|\s|>)(ge\s*appliances)(?:\s|$|<)",
    
    # TV Brands
    "Sony": r"(?:^|\s|>)(sony)(?:\s|$|<)",
    "Panasonic": r"(?:^|\s|>)(panasonic)(?:\s|$|<)",
    "Vizio": r"(?:^|\s|>)(vizio)(?:\s|$|<)",
    "TCL": r"(?:^|\s|>)(tcl)(?:\s|$|<)",
    "Hisense": r"(?:^|\s|>)(hisense)(?:\s|$|<)",
    "Philips": r"(?:^|\s|>)(philips)(?:\s|$|<)",
    
    # DVR Boxes / Set-top Boxes
    "TiVo": r"(?:^|\s|>)(tivo)(?:\s|$|<)",
    "Dahua": r"(?:^|\s|>)(dahua)(?:\s|$|<)",
    "Hikvision": r"(?:^|\s|>)(hikvision)(?:\s|$|<)",
    "Swann": r"(?:^|\s|>)(swann)(?:\s|$|<)",

    # Printers
    "HP": r"(?:^|\s|>)(hp)(?:\s|$|<)",
    "Canon": r"(?:^|\s|>)(canon)(?:\s|$|<)",
    "Brother": r"(?:^|\s|>)(brother)(?:\s|$|<)",
    "Epson": r"(?:^|\s|>)(epson)(?:\s|$|<)",
}

operator_patterns = [
    r"(?:^|\s|>)(verizon)(?:\s|$|<)",
    r"(?:^|\s|>)(at\s*&\s*t)(?:\s|$|<)",  # "AT&T"
    r"(?:^|\s|>)(comcast)(?:\s|$|<)",
    r"(?:^|\s|>)(telekom)(?:\s|$|<)",
    r"(?:^|\s|>)(vodafone)(?:\s|$|<)",
    r"(?:^|\s|>)(telia)(?:\s|$|<)",
    r"(?:^|\s|>)(centurylink)(?:\s|$|<)",
    r"(?:^|\s|>)(sprint)(?:\s|$|<)",
    r"(?:^|\s|>)(tmobile)(?:\s|$|<)",
    r"(?:^|\s|>)(telefonica)(?:\s|$|<)",
    r"(?:^|\s|>)(china\s*telecom)(?:\s|$|<)",
    r"(?:^|\s|>)(china\s*unicom)(?:\s|$|<)",
    r"(?:^|\s|>)(bt\s*group)(?:\s|$|<)",  # British Telecom
    r"(?:^|\s|>)(orange)(?:\s|$|<)",
    r"(?:^|\s|>)(bell\s*canada)(?:\s|$|<)",
    r"(?:^|\s|>)(rogers)(?:\s|$|<)",
    r"(?:^|\s|>)(shaw)(?:\s|$|<)",
    r"(?:^|\s|>)(sasktel)(?:\s|$|<)",
    r"(?:^|\s|>)(cox\s*communications)(?:\s|$|<)",
]

model_regexes = [
    # e.g., "Model: ABC123"
    r"model\s*:\s*([^\s<]+)",
    # e.g., "Model ABC123"
    r"model\s+([^\s<]+)",
    r"modelName=\"(.*?)\"",
    r"modelDesc=\"(.*?)\"",
    # e.g., "RB2011", "RB750Gr3" for Mikrotik
    r"\b(RB\d+\w*)\b",
    # e.g., "FRITZ!Box 7490" for AVM
    r"(fritz!box\s*\d+[^\s<]*)",
    r"\b(dvr)\b",
    r"\b(NVR\d+-\d+[A-Z0-9]+)\b", #UNV NVR301-16S3 network video recorder
    # e.g., <li id="product_name">HG255s</li>
    r"<li[^>]*id=[\"']product_name[\"'][^>]*>([^<]+)</li>",
    r"src=[\"\'']/configHtml\.js\?v=[^\"\'<>]*?(\bWOM MiMo\b)[^\"\'<>]*?[\"\'']",
    r"\b(?:Brother|Canon|HP|Epson) ([^/\s,]+(?: [^/\s,]+)*)\b",
]

firmware_regexes = [
    # e.g., "Firmware Version 1.2.3" or "Firmware 1.2.3"
    r"(?<![/\-])firmware(?:\s*version)?\s*[:=]?\s*([\d\.]+[^\s<]*)",
    r"Firmware (Ver\.[\d\.]+)",
    # e.g., "RouterOS 6.45.1"
    r"(routeros(?:\s*\d+\.\d+(\.\d+)?)?)",
    r"(v\d+\.\d+(\.\d+)?)",
    # e.g., "OpenWrt Chaos Calmer 15.05"
    r"(openwrt\s*\w+\s*\d+\.\d+)",
    # DD-WRT (e.g., "DD-WRT v3.0")
    r"(dd[-\s]?wrt(?:\s*v?[\d\.]+)?)",
    # Tomato (e.g., "Tomato 1.28")
    r"(tomato(?:\s*[vV]?[\d\.]+)?)",
    # Gargoyle (e.g., "Gargoyle 1.12")
    r"(gargoyle(?:\s*[vV]?[\d\.]+)?)",
    # Asuswrt or Merlin (e.g., "Asuswrt-Merlin 384.19")
    r"(asuswrt(?:[-\s]?merlin)?(?:\s*[vV]?[\d\.]+)?)",
    # pfSense (e.g., "pfSense 2.4.5")
    r"(pfsense(?:\s*[vV]?[\d\.]+)?)",
    # OPNsense (e.g., "OPNsense 20.7")
    r"(opnsense(?:\s*[vV]?[\d\.]+)?)",
    # LEDE (often used interchangeably with OpenWrt, but might appear separately)
    r"(lede(?:\s*[vV]?[\d\.]+)?)",
]

def find_router_vendor(banner_text):
    matches = []
    text_lower = banner_text.lower()
    for vendor, pattern in vendor_patterns.items():
        if re.search(pattern, text_lower):
            if vendor not in matches:
                matches.append(vendor)
    return ",".join(matches)

def find_model_version(banner_text):
    if "PID:" in banner_text:
        match = re.search(r"PID:\s*([^,\n]+)\b", banner_text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    matches = []
    for pattern in model_regexes:
        match = re.search(pattern, banner_text, re.IGNORECASE)
        if match:
            modelv = match.group(1).strip()
            if modelv == "=": continue
            if modelv not in matches:
                matches.append(modelv)
    return ",".join(matches)

def find_firmware_version(banner_text):
    matches = []
    for pattern in firmware_regexes:
        match = re.search(pattern, banner_text, re.IGNORECASE)
        if match:
            version = match.group(1).strip()
            if ".cgi" in version:
                print(match)
                input()
            if version not in matches:
                matches.append(version)
    return ",".join(matches)

def find_network_operator(banner_text):
    matches = []
    text_lower = banner_text.lower()
    for op_pattern in operator_patterns:
        match = re.search(op_pattern, text_lower, re.IGNORECASE)
        if match:
            operator = match.group(1).strip()
            if operator not in matches:
                matches.append(operator)
    return ",".join(matches)

def analyze_str(ip_address, banner_content, successful_protocols):
    # grab device characteristics with regex
    router_vendor = find_router_vendor(banner_content)
    model_version = find_model_version(banner_content)
    firmware_version = find_firmware_version(banner_content)
    network_operator = find_network_operator(banner_content)

    if router_vendor == "" and "NVR" in model_version:
        router_vendor = "UNV"

    row = {
        headers[0]: ip_address,
        headers[1]: network_operator,
        headers[2]: router_vendor,
        headers[3]: model_version,
        headers[4]: firmware_version,
        headers[5]: ",".join(successful_protocols),
        headers[6]: hash_string(banner_content)
    }

    return row

def analyze_str_snmp(ip_address, banner_content):
    # grab device characteristics with regex
    router_vendor = find_router_vendor(banner_content)
    if "RouterOS" in banner_content:
        split_model = banner_content.split(" ", 1)
        if len(split_model) == 2:
            model_version = split_model[1]
    else:
        model_version = find_model_version(banner_content)
        if model_version == "":
            model_version = banner_content.replace(",", "").replace(";", "")
    firmware_version = find_firmware_version(banner_content)
    network_operator = find_network_operator(banner_content)

    if router_vendor == "" and "NVR" in model_version:
        router_vendor = "UNV"

    row = {
        headers[0]: ip_address,
        headers[1]: network_operator,
        headers[2]: router_vendor,
        headers[3]: model_version,
        headers[4]: firmware_version,
        headers[5]: "snmp",
        headers[6]: hash_string(banner_content)
    }

    return row

def parse_html_output(input_html_path, output_csv_path):
    with open(output_csv_path, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=headers, delimiter=";")
        writer.writeheader()
        for filename in tqdm(os.listdir(input_html_path)):
            filepath = os.path.join(input_html_path, filename)
            if os.path.isfile(filepath):
                with open(filepath, "r") as file:
                    file_content = file.read()
                    row = analyze_str(filename[:-5],file_content,"")
                    writer.writerow(row)
    print(f"CSV output written to: {output_csv_path}")

def parse_zgrab_output(input_json_path, output_csv_path):
    with open(input_json_path, "r", encoding="utf-8") as infile:
        total_lines = sum(1 for _ in infile)

    with open(input_json_path, "r", encoding="utf-8") as infile, \
         open(output_csv_path, "w", newline="", encoding="utf-8") as outfile:

        writer = csv.DictWriter(outfile, fieldnames=headers, delimiter=";")
        writer.writeheader()

        for line in tqdm(infile, total=total_lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # extract ip or domain
            ip_address = record.get("ip") or record.get("domain") or ""

            # data_section typically holds sub-results for each configured probe
            data_section = record.get("data", {})

            successful_protocols = []
            combined_banners = []

            # HTTP 80
            http80_data = data_section.get("http80")
            if http80_data and http80_data.get("status","") != "connection-timeout":
                successful_protocols.append("http80")
                body_text = (http80_data["result"]
                                        .get("response", {})
                                        .get("body", ""))
                if body_text:
                    combined_banners.append(body_text)

            # HTTP 8080
            http8080_data = data_section.get("http8080")
            if http8080_data and http8080_data.get("status","") != "connection-timeout":
                successful_protocols.append("http8080")
                body_text = (http8080_data["result"]
                                         .get("response", {})
                                         .get("body", ""))
                if body_text:
                    combined_banners.append(body_text)

            # HTTPS 443
            https443_data = data_section.get("https443")
            if https443_data and https443_data.get("status","") != "connection-timeout":
                successful_protocols.append("https443")
                body_text = (https443_data["result"]
                                         .get("response", {})
                                         .get("body", ""))
                if body_text:
                    combined_banners.append(body_text)

            # SSH
            ssh_data = data_section.get("ssh")
            if ssh_data and ssh_data.get("status","") != "connection-timeout":
                successful_protocols.append("ssh")
                banner = ssh_data["result"].get("metadata", {}).get("banner", "")
                if banner:
                    combined_banners.append(banner)
                server_id = ssh_data["result"].get("server_id", {}).get("software","")
                if server_id:
                    combined_banners.append(server_id)

            # combine banner text
            big_banner_text = "\n".join(combined_banners)

            row = analyze_str(ip_address, big_banner_text, successful_protocols)

            writer.writerow(row)

    print(f"CSV output written to: {output_csv_path}")

def parse_onesixtyone_output(inpath, outpath):
    with open(inpath, "r", encoding="utf-8") as infile:
        total_lines = sum(1 for _ in infile)

    with open(inpath, "r", encoding="utf-8") as infile, \
         open(outpath, "w", newline="", encoding="utf-8") as outfile:

        writer = csv.DictWriter(outfile, fieldnames=headers, delimiter=";")
        writer.writeheader()

        ips = []

        for line in tqdm(infile, total=total_lines):
            match = re.search(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[[^\]]+\] (.+)$", line, re.IGNORECASE)
            if match:
                ip = match.group(1).strip()
                if ip in ips: continue
                ips.append(ip)
                snmp_desc = match.group(2).strip()
                row = analyze_str_snmp(ip, snmp_desc)
                writer.writerow(row)
    print(f"CSV output written to: {outpath}")


if __name__ == "__main__":
    parser.add_argument("-m", "--mode", type=str, help="zgrab, selenium, snmp")
    parser.add_argument("-i", "--input", type=str, help="path to input file/folder")
    parser.add_argument("-o", "--output", type=str, help="path to output file")
    args, leftovers = parser.parse_known_args()
    if args.mode is None :
        print("mode missing --mode")
        sys.exit(1)
    if args.input is None:
        print("input path missing --input")
        sys.exit(1)

    if args.mode == "selenium": 
        parse_html_output(args.input, args.output if args.output is not None else "parsed_results_html.csv")
    elif args.mode == "zgrab":
        parse_zgrab_output(args.input, args.output if args.output is not None else "parsed_results.csv")
    elif args.mode == "snmp":
        parse_onesixtyone_output(args.input, args.output if args.output is not None else "parsed_results_snmp.csv")
