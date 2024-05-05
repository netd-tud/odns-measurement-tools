from dataclasses import dataclass
from tqdm import tqdm
import glob
from ipaddress import ip_address
from enum import Enum
import gzip
import sys
from threading import Thread
import time

from queue import Queue,Empty

QUEUE = Queue()
# this will more or less represent a single row of the output csv
@dataclass
class OutputItem:
    target_ip: ip_address
    response_ip: ip_address
    arecord: ip_address
    timestamp: str
    odns_type: str

# only select the columns actually needed
class InPos(Enum):
    TS    = 1
    SIP   = 2
    IP    = 4
    ID    = 5
    SP    = 6
    DP    = 7
    FLAGS = 8
    QNAME = 20
    RNAME = 21
    RECS  = 23

def writer_thread(save_fname):
    # writeout
    with open(save_fname, "w", encoding="utf-8") as out_file:
        while True:
            try:
                item = QUEUE.get(timeout=10)
            except Empty as e:
                break
            out_file.write(f"{item.target_ip};{item.response_ip};{item.arecord};{item.timestamp};{item.odns_type}\n")

# input csv id is key
output_df: dict[int, OutputItem]= {}

def process_line(split):
    key =  (split[InPos.ID.value],int(split[InPos.DP.value]))  
    if key not in output_df:
        return
    arecs = split[InPos.RECS.value].split(',')
    # there should be two entries, one of them the control ip
    if len(arecs) != 2 or "91.216.216.216" not in arecs:
        return
    arecord = arecs[0] if arecs[1]=="91.216.216.216" else arecs[1]
    outitem = output_df[(split[InPos.ID.value],int(split[InPos.DP.value]))]
    outitem.response_ip = split[InPos.SIP.value]
    outitem.arecord = arecord
    if outitem.response_ip != outitem.target_ip:
        outitem.odns_type = 'Transparent Forwarder'
    elif outitem.arecord == outitem.response_ip:
        outitem.odns_type = 'Resolver'
    else:
        outitem.odns_type = 'Forwarder'
    QUEUE.put(outitem)

    del output_df[(split[InPos.ID.value],int(split[InPos.DP.value]))]


if __name__ == "__main__":
    if len(sys.argv) == 3:
        pattern = sys.argv[1]
        save_fname = sys.argv[2]
    else:
        print("call like this: python postproc_data_tcp_pure.py </dir/file_pattern> <output_file>")
        exit(1)
    start_t = time.time()
    print('setting thread...')
    thread = Thread(target=writer_thread,args=[save_fname])
    print('Starting thread...')
    thread.start()
    print("thread started.")
    files = glob.glob(pattern)
    files.sort() # this is important because the rest of the script depends on the file names being in alphabetical order
    print(f"files[0]={files[0]},files[1]={files[1]}")
    print('read file list')

    for i in tqdm(range(len(files))):
        #iteration 1: only process DNS responses
        #iteration 2: process all requests AND responses from file i
        #we want to read in 2 subsequent files to match request with responses -> take all requests and responses from file one and only the responses from file 2 to match them with file 1
        for j in range(2):
            if j==0 and i==0:
                continue
            load_fname = files[i]
            with gzip.open(load_fname, 'rt', encoding="utf-8") as input_file:
                while line := input_file.readline():
                    line = line.replace('"','')
                    split = line.strip().split(";")
                    if 'rr-mirror.research.nawrocki.berlin' not in [split[InPos.RNAME.value],split[InPos.QNAME.value]]:
                        ##print('continue',split)
                        continue
                    if int(split[InPos.FLAGS.value])==1:
                        ##print(split)
                        process_line(split)
                    elif j==1:
                        outitem = OutputItem(split[InPos.IP.value],None, None, split[InPos.TS.value],"")
                        output_df[(split[InPos.ID.value],int(split[InPos.SP.value]))] = outitem
            if j==0:
                output_df = {}
    thread.join()
    print("done")
    end_t = time.time()
    print(f"took:{end_t-start_t}s")
