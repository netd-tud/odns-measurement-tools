import os
import sys
import csv
from collections import defaultdict
from common import hash_string

headers = [
    "ip", 
    "network-operator", 
    "router-vendor", 
    "model-version", 
    "firmware-version", 
    "successful-protocols",
    "banner-hash",
]

if len(sys.argv) > 2:
    # merged data
    data = defaultdict(lambda: defaultdict(set))

    # read csv and merge into dataframe
    def read_csv_to_dict(filename):
        with open(filename, newline="", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=";")
            headers = next(reader)  # column header
            for row in reader:
                id_key = row[0]  # first column is key (=IP)
                for col_index in range(1, len(headers)):  # iterate remaining rows
                    column_name = headers[col_index]
                    values = row[col_index].split(",")  # split on comma
                    data[id_key][column_name].update(values)  # merge unique values
                    if "" in  data[id_key][column_name] and len(data[id_key][column_name]) > 1:
                        data[id_key][column_name].remove("")

    for file_arg in sys.argv[1:]:
        read_csv_to_dict(file_arg)

    all_columns = [headers[0]] + list(next(iter(data.values())).keys())

    # write back
    with open("combined_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(all_columns)  # headers
        
        for id_key in sorted(data.keys()):
            row = [id_key] # write key column
            for column in all_columns[1:]:  # write remainin
                if "hash" in column:
                    row.append(hash_string(",".join(sorted(data[id_key].get(column, set())))))
                else:
                    row.append(",".join(sorted(data[id_key].get(column, set()))))  # merge all unique
            writer.writerow(row)

import polars as pl
df = pl.read_csv("combined_results.csv", separator=";")
df = df.with_columns(
    df["ip"].str.extract(r"^(.*)\.[^.]+$", 1).alias("network-24")
)
df_grouped = df.filter(pl.col("router-vendor").is_not_null()).group_by(["network-24","router-vendor", "model-version", "successful-protocols", "banner-hash"]).agg(
    pl.len().alias("no-of-ips")
).sort(by="no-of-ips", descending=True)
df_grouped.write_csv("fingerprinting_dealiased.csv", separator=";") 