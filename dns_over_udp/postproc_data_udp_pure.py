from dataclasses import dataclass
from tqdm import tqdm
import glob
from ipaddress import ip_address
from enum import Enum
import gzip
import sys
from multiprocessing import Process, Queue, Value, Lock
from threading import Thread
import time
#from queue import Queue, Empty
from typing import Dict, List, Tuple

##### vars #####
# file 1: process all requests AND responses from file first file
# file 2: only process DNS responses
# we want to read in 2 subsequent files to match request with responses 
# -> take all requests and responses from file one and only the responses from file 2 to match them with file 1
# increasing this value will match file 1 with more than 1 other file 
NO_OF_FILES = 2
REFERENCE_QUERY_NAME = 'rr-mirror.research.nawrocki.berlin'
THREAD_COUNT = 6
################

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
    RESP_FLAG = 8
    QNAME = 20
    RNAME = 21
    RECS  = 23

def writer_thread(save_fname):
    # writeout
    with open(save_fname, "w", encoding="utf-8") as out_file:
        while True:
            item = QUEUE.get()
            if item is None: # sentinel
                break
            out_file.write(f"{item.target_ip};{item.response_ip};{item.arecord};{item.timestamp};{item.odns_type}\n")

class WorkerProcess(Process):
    def __init__(self, pid: int, writeout_q :Queue, files_pos, files_pos_lock):
        super().__init__()
        self._pid = pid
        self._writeout_q = writeout_q
        self._files_pos = files_pos
        self._files_pos_lock = files_pos_lock

    def process_line(self, output_df: Dict[Tuple[int, str], OutputItem], csv_split: List[str]):
        key =  (csv_split[InPos.ID.value],int(csv_split[InPos.DP.value]))  
        if key not in output_df:
            return
        arecs = csv_split[InPos.RECS.value].split(',')
        # there should be two entries, one of them the control ip
        if len(arecs) != 2 or "91.216.216.216" not in arecs:
            return
        arecord = arecs[0] if arecs[1]=="91.216.216.216" else arecs[1]
        outitem = output_df[(csv_split[InPos.ID.value],int(csv_split[InPos.DP.value]))]
        outitem.response_ip = csv_split[InPos.SIP.value]
        outitem.arecord = arecord
        if outitem.response_ip != outitem.target_ip:
            outitem.odns_type = 'Transparent Forwarder'
        elif outitem.arecord == outitem.response_ip:
            outitem.odns_type = 'Resolver'
        else:
            outitem.odns_type = 'Forwarder'
        self._writeout_q.put(outitem)

        del output_df[(csv_split[InPos.ID.value],int(csv_split[InPos.DP.value]))] 

    def process_file(self, idx: int):
        """
        idx: index of the file to be read
        """
        self.print(f"processing file {idx+1}")
        # input csv id is key
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
                        self.process_line(output_df, split)
                    elif offset==0: # request (for everything except the first file we only want the responses)
                        outitem = OutputItem(split[InPos.IP.value],None, None, split[InPos.TS.value],"")
                        output_df[(split[InPos.ID.value],int(split[InPos.SP.value]))] = outitem

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
    files_pos = Value('i', 0)
    files_pos_lock = Lock()
    writeout_thread = Thread(target=writer_thread,args=[save_fname])
    print('starting writeout thread...')
    writeout_thread.start()
    files = glob.glob(pattern)
    files.sort() # this is important because the rest of the script depends on the file names being in alphabetical order
    print(f"files[0]={files[0]},files[1]={files[1]}")
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

    writeout_thread.join()
    print("done")
    end_t = time.time()
    print(f"took:{end_t-start_t}s")
