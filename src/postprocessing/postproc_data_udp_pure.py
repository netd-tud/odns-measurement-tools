from dataclasses import dataclass
import glob
from ipaddress import ip_address
from enum import Enum
import gzip
import sys
from multiprocessing import Process, Queue, Value, Lock
from threading import Thread
import time
import os
from typing import Dict, List, Tuple
from natsort import natsorted

##### vars #####
# file 1: process all requests AND responses from file first file
# file 2: only process DNS responses
# we want to read in 2 subsequent files to match request with responses 
# -> take all requests and responses from file one and only the responses from file 2 to match them with file 1
# increasing this value will match file 1 with more than 1 other file 
NO_OF_FILES = 2
REFERENCE_QUERY_NAME = 'rr-mirror.research.nawrocki.berlin'
REFERENCE_IP = "91.216.216.216"
THREAD_COUNT = 15
################

QUEUE = Queue()
# this will more or less represent a single row of the output csv
@dataclass
class OutputItem:
    id: str
    target_ip: ip_address
    response_ip: ip_address
    arecord: ip_address
    odns_type: str
    timestamp_req: str
    timestamp_resp: str
    port: int
    dnsid: int
    dns_pkt_size: int
    dns_rrs: str
    dns_flags: int
    dns_ttl: int

    def classify(self):
        if self.response_ip != self.target_ip:
            self.odns_type = 'Transparent Forwarder'
        elif self.arecord == self.response_ip:
            self.odns_type = 'Resolver'
        else:
            self.odns_type = 'Forwarder'

# only select the columns actually needed
class InPos(Enum):
    TS    = 1
    SIP   = 2
    IP    = 4
    ID    = 5
    SP    = 6
    DP    = 7
    RESP_FLAG = 8
    QNAME = 20
    RNAME = 21
    RECS  = 23

class GoPos(Enum):
    ID        = 0
    TARGET_IP = 1
    RESP_IP   = 2
    AREC_IP   = 3
    TS_REQ    = 4
    TS_RESP   = 5
    PORT      = 6
    DNSID     = 7
    PKT_SIZE  = 8
    RRS       = 9
    FLAGS     = 10
    DNS_TTL   = 11


def writer_thread(save_fname: str):
    # writeout
    with open(save_fname, "w", encoding="utf-8") as out_file:
        print("writer file opened")
        while True:
            item: OutputItem = QUEUE.get()
            if item is None: # sentinel
                break
            out_file.write(f"{item.id}"
                           f";{item.target_ip}"
                           f";{item.response_ip}"
                           f";{item.arecord}"
                           f";{item.odns_type}"
                           f";{item.timestamp_req}"
                           f";{item.timestamp_resp}"
                           f";{item.dns_flags}"
                           f";{item.dns_ttl}"
                           "\n")

def process_go_results(load_fname: str):
    with gzip.open(load_fname, 'rt', encoding="utf-8") as input_file:
        while line := input_file.readline():
            line = line.replace('"','')
            split = line.strip().split(";")
            try:
                if split[GoPos.AREC_IP.value] == "":
                    continue
                arecs = split[GoPos.AREC_IP.value].split(',')
                # there should be two entries, one of them the control ip
                if len(arecs) != 2 or REFERENCE_IP not in arecs:
                    continue
                arecord = ip_address(arecs[0] if arecs[1]==REFERENCE_IP else arecs[1])
                outitem = OutputItem(
                    split[GoPos.ID.value],
                    ip_address(split[GoPos.TARGET_IP.value]),
                    ip_address(split[GoPos.RESP_IP.value]),
                    arecord,
                    "",
                    split[GoPos.TS_REQ.value],
                    split[GoPos.TS_RESP.value] if len(split) >= 6 else "",
                    split[GoPos.PORT.value] if len(split) >= 7 else -1,
                    split[GoPos.DNSID.value] if len(split) >= 8 else -1,
                    split[GoPos.PKT_SIZE.value] if len(split) >= 9 else -1,
                    split[GoPos.RRS.value] if len(split) >= 10 else "",
                    split[GoPos.FLAGS.value] if len(split) >= 11 else -1,
                    split[GoPos.DNS_TTL.value] if len(split) >= 12 else -1
                )
                outitem.classify()
                QUEUE.put(outitem)
            except ValueError:
                continue


class WorkerProcess(Process):
    def __init__(self, pid: int, writeout_q :Queue, files_pos, files_pos_lock):
        super().__init__()
        self._pid = pid
        self._writeout_q = writeout_q
        self._files_pos = files_pos
        self._files_pos_lock = files_pos_lock

    def process_resp_line(self, output_df: Dict[Tuple[int, str], OutputItem], csv_split: List[str]):
        key =  (csv_split[InPos.ID.value],int(csv_split[InPos.DP.value]))  
        if key not in output_df:
            return
        arecs = csv_split[InPos.RECS.value].split(',')
        # there should be two entries, one of them the control ip
        if len(arecs) != 2 or REFERENCE_IP not in arecs:
            return
        arecord = ip_address(arecs[0] if arecs[1]==REFERENCE_IP else arecs[1])
        outitem = output_df[(csv_split[InPos.ID.value],int(csv_split[InPos.DP.value]))]
        outitem.response_ip = ip_address(csv_split[InPos.SIP.value])
        outitem.arecord = arecord
        outitem.classify()
        self._writeout_q.put(outitem)
        del output_df[(csv_split[InPos.ID.value],int(csv_split[InPos.DP.value]))]

    def process_file(self, idx: int):
        """
        idx: index of the file to be read
        """
        self.print(f"processing file {idx+1}")
        output_df: Dict[(int, str), OutputItem]= {}
        for offset in range(NO_OF_FILES):
            if idx+offset > len(files)-1:
                break
            load_fname = files[idx+offset]
            with gzip.open(load_fname, 'rt', encoding="utf-8") as input_file:
                while line := input_file.readline():
                    line = line.replace('"','')
                    split = line.strip().split(";")
                    if REFERENCE_QUERY_NAME not in [split[InPos.RNAME.value],split[InPos.QNAME.value]]:
                        continue
                    if int(split[InPos.RESP_FLAG.value])==1: # response
                        self.process_resp_line(output_df, split)
                    elif offset==0: # request (for everything except the first file we only want the responses)
                        outitem = OutputItem("",ip_address(split[InPos.IP.value]),None, None, split[InPos.TS.value],"")
                        output_df[(split[InPos.ID.value],int(split[InPos.SP.value]))] = outitem
                    elif offset!=0 and (split[InPos.ID.value],int(split[InPos.SP.value])) in output_df.keys():
                        # zmap might have already reused this port and dnsid -> so if there is a request with the same key already in the dict, this one is removed
                        del output_df[(split[InPos.ID.value],int(split[InPos.SP.value]))]

    def run(self):
        while True:
            with self._files_pos_lock:
                if self._files_pos.value == len(files):
                    break
                file_idx = self._files_pos.value
                self._files_pos.value = self._files_pos.value +1
            self.process_file(file_idx)

    def print(self, msg: str):
        print(f"[{self._pid}] {msg}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        pattern = sys.argv[1]
        save_fname = sys.argv[2]
    else:
        print("call like this: python postproc_data_tcp_pure.py </dir/file_pattern> <output_file>")
        exit(1)
    start_t = time.time()
    writeout_thread = Thread(target=writer_thread,args=[save_fname])
    print('starting writeout thread...')
    writeout_thread.start()
    # if the pattern is actually a file then the results of the gofile should be processed 
    if os.path.isfile(pattern):
        print("go script mode")
        process_go_results(load_fname=pattern)
    # otherwise the results of the zmap scan (which is more complicated)
    else:
        print("zmap script mode")
        files_pos = Value('i', 0)
        files_pos_lock = Lock()
        files = glob.glob(pattern)
        tempfiles = natsorted(files) # this is important because the rest of the script depends on the file names being in alphabetical order
        files = tempfiles
        print(f"files[0]={files[0]},files[1]={files[1]},files[2]={files[2]}")
        print('read file list')

        worker_pool: List[WorkerProcess] = []
        for pid in range(THREAD_COUNT):
            print(f"starting worker process {pid}")
            worker = WorkerProcess(pid, QUEUE, files_pos, files_pos_lock)
            worker_pool.append(worker)
            worker.start()
        
        for worker in worker_pool:
            worker.join()
        print("all workers ended")

    QUEUE.put(None) # ends the writer
    writeout_thread.join()
    print("done")
    end_t = time.time()
    print(f"took:{end_t-start_t}s")
