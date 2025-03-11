package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/f10d0/bpfutils"
	"github.com/ilyakaznacheev/cleanenv"
)

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)

const (
	debug = true
)

// config
type cfg_db struct {
	Iface_name string `yaml:"iface_name"`
	Iface_ip   string `yaml:"iface_ip"`
	Dst_port   uint16 `yaml:"dst_port"`
}

var cfg cfg_db
var wg sync.WaitGroup
var pcap_counter = 0
var pcap_file *os.File
var pcap_writer *pcapgo.Writer
var pcap_basename = "udpdump"
var pcap_part_size = 300 * 1024 * 1024
var dump_path string

func load_config() {
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		panic(err)
	}
	if debug {
		log.Println("config:", cfg)
	}
}

func zipndel(file *os.File) {
	log.Println("zipping file:", file.Name())
	gzip_file, err := os.Create(file.Name() + ".gz")
	if err != nil {
		panic(err)
	}
	defer gzip_file.Close()
	gzip_writer := gzip.NewWriter(gzip_file)
	defer gzip_writer.Close()

	// copy the file
	file.Close()
	readfile, _ := os.Open(file.Name())
	_, err = io.Copy(gzip_writer, readfile)
	if err != nil {
		panic(err)
	}

	log.Println("deleting file:", file.Name())
	os.Remove(file.Name())
}

func check_writer() {
	defer wg.Done()
	for {
		select {
		case <-time.After(1 * time.Second):
			stat, err := pcap_file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			if stat.Size() > int64(pcap_part_size) {
				log.Println("size exceeded, creating new pcap file")
				cur_pcap_file := pcap_file
				new_filename := pcap_basename + strconv.Itoa(pcap_counter) + ".pcap"
				log.Println("new filename:", new_filename)
				new_pcap_file, err := os.Create(path.Join(dump_path, new_filename))
				if err != nil {
					log.Fatal(err)
				}

				new_pcap_writer := pcapgo.NewWriter(new_pcap_file)
				if err := new_pcap_writer.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
					log.Fatalf("WriteFileHeader: %v", err)
				}
				pcap_file = new_pcap_file
				pcap_writer = new_pcap_writer
				pcap_counter++
				// close & zip the previous file
				time.Sleep(500 * time.Millisecond)
				zipndel(cur_pcap_file)
			}
		case <-stop_chan:
			return
		}
	}
}

func packet_capture(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	if debug {
		log.Println("starting packet capture")
	}

	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			// actual dump
			if err := pcap_writer.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
				log.Fatalf("pcap.WritePacket(): %v", err)
			}
		case <-stop_chan:
			if debug {
				log.Println("stopping packet capture")
			}
			return
		}
	}
}

func main() {
	load_config()
	// command line args
	if len(os.Args) < 2 {
		log.Println("path missing")
		return
	}
	dump_path = os.Args[1]
	os.MkdirAll(dump_path, 0755)

	// handle ctrl+c SIGINT
	go func() {
		interrupt_chan := make(chan os.Signal, 1)
		signal.Notify(interrupt_chan, os.Interrupt)
		<-interrupt_chan
		close(stop_chan)
	}()
	// start packet capture
	handle, err := pcapgo.NewEthernetHandle(cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, fmt.Sprint("udp and port ", cfg.Dst_port))
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	// setup first writer
	new_filename := pcap_basename + strconv.Itoa(pcap_counter) + ".pcap"
	log.Println("initializing pcap file:", new_filename)
	new_pcap_file, err := os.Create(path.Join(dump_path, new_filename))
	if err != nil {
		log.Fatal(err)
	}
	pcap_file = new_pcap_file
	pcap_writer = pcapgo.NewWriter(pcap_file)
	if err := pcap_writer.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}
	pcap_counter++

	wg.Add(2)
	go check_writer()
	go packet_capture(handle)
	wg.Wait()
	zipndel(pcap_file)
	log.Println("done")
}
