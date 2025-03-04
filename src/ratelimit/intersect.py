#! ../../venv/bin/python
import sys
import os
import pandas as pd
import numpy as np
import socket, struct

def ip2long(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]

def long2ip(ip):
    return socket.inet_ntoa(struct.pack('!L', ip))

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("check input args: python intersect.py <resolvers_scan_file> <complete_scan_file> <output_file>")
    
    resolvers_scan_fname = sys.argv[1]
    complete_scan_fname = sys.argv[2]
    output_fname = sys.argv[3]

    if not os.path.isfile(resolvers_scan_fname) or not os.path.isfile(complete_scan_fname):
        print("one of the input files does not exist")
        exit(1)
    
    # pandas part
    # read the two files as dataframes
    resolver_df = pd.read_csv(resolvers_scan_fname, sep=';', names=['id','ip_request','ip_response','a_record','ts','port','dnsid'], usecols=['ip_response','a_record'], converters={"ip_response":ip2long})
    resolver_df = resolver_df[resolver_df['a_record'].notna()]
    resolver_df = resolver_df[resolver_df.a_record.str.contains("91.216.216.216")] # sanity check
    print(resolver_df.head())
    resolver_df = resolver_df.drop("a_record", axis=1)
    scan_df = pd.read_csv(complete_scan_fname, sep=';', converters={"ip_response":ip2long})
    scan_df = scan_df[scan_df["response_type"] == "Transparent Forwarder"]
    print(scan_df.head())
    print("dataframes read")

    # join on common response ips
    not_intersect_df = pd.merge(scan_df, resolver_df, indicator=True, how='outer').query('_merge=="left_only"').drop('_merge', axis=1)
    not_intersect_df['ip_response'] = not_intersect_df['ip_response'].apply(lambda ip: long2ip(ip))
    print(not_intersect_df)
    not_intersect_df.to_csv(output_fname, sep=";", index=False)