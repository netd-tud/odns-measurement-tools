package ratelimit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/time/rate"
)

const (
	csv_target_ip     int = 1
	csv_response_ip   int = 2
	csv_response_type int = 4
)

type Answer_entry struct {
	ts               int64
	dns_payload_size int
}

type Resolver_entry struct {
	resolver_ip     net.IP
	tfwd_ips        []net.IP // ip pool
	tfwd_pool_pos   int
	rate_pos        int            // the current pos in the rate slice aka the current send rate
	rate_limiter    *rate.Limiter  // current rate limiter
	answer_data     []Answer_entry // us, answer timestamps, log timestamp of every incoming packet
	answer_mu       sync.Mutex
	moving_avg_rate float64
	max_rate        float64
	outport         uint16
}

type Resolver_key struct {
	resolver_ip string
}

type Active_key struct {
	port uint16
}

type Rate_tester struct {
	common.Base
	udp_common.Udp_binder
	udp_common.Udp_sender
	resolver_data      map[Resolver_key]*Resolver_entry
	resolver_mu        sync.Mutex
	active_resolvers   map[Active_key]*Resolver_entry
	finished_resolvers chan *Resolver_entry
	sender_wg          sync.WaitGroup
	increase_interval  int // time delay between rate increases [ms]
	rate_curve         []int
	current_port       uint32
	resolver_counter   int
	rec_thres          float64
}

func (entry *Resolver_entry) calc_last_second_rate(tester *Rate_tester) {
	now := time.Now().UnixMicro()
	// calculate avg receive rate
	ans_len := len(entry.answer_data) - 1
	i := ans_len
	for ; i >= 0; i-- {
		if entry.answer_data[i].ts < now-int64(tester.increase_interval)*1000 {
			break
		}
	}
	entry.moving_avg_rate = float64(ans_len-i) / float64(tester.increase_interval) * 1000
	entry.max_rate = common.Max(entry.max_rate, entry.moving_avg_rate)
}

func (tester *Rate_tester) write_results(out_path string) {
	formatted_ts := time.Now().UTC().Format("2006-01-02_15-04-05")
	out_path = path.Join(out_path, formatted_ts)
	os.MkdirAll(out_path, os.ModePerm)
	for {
		select {
		case entry := <-tester.finished_resolvers:
			csvfile, err := os.Create(path.Join(out_path, entry.resolver_ip.String()+".csv.gz"))
			if err != nil {
				panic(err)
			}
			zip_writer := gzip.NewWriter(csvfile)
			csv_writer := csv.NewWriter(zip_writer)
			csv_writer.Comma = ';'

			logging.Println(5, nil, "writing entry for resolver", entry.resolver_ip)
			var record []string
			// === csv format ===
			// line 1: resolver_ip, max_rate, avg_rate
			record = append(record, entry.resolver_ip.String())
			record = append(record, strconv.Itoa(int(entry.max_rate)))
			record = append(record, strconv.Itoa(int(entry.moving_avg_rate)))
			csv_writer.Write(record)
			// line 2: ts 1?
			// line 3: ts 2
			// ...
			// line n: ts n
			for _, ans_entry := range entry.answer_data {
				record = make([]string, 2)
				record[0] = strconv.FormatInt(ans_entry.ts, 10)
				record[1] = strconv.Itoa(ans_entry.dns_payload_size)
				csv_writer.Write(record)
			}

			csv_writer.Flush()
			zip_writer.Close()
			csvfile.Close()
		case <-tester.Stop_chan:
			return
		}
	}
}

func (tester *Rate_tester) Read_forwarders(fname string) {
	logging.Println(3, nil, "reading forwarders from", fname)
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	gzip_reader, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}
	defer gzip_reader.Close()

	scanner := bufio.NewScanner(gzip_reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			logging.Println(6, nil, "line empty")
			continue
		}
		// split csv columns
		split := strings.Split(line, ";")
		if split[csv_response_type] != "Transparent Forwarder" {
			continue
		}
		//logging.Println(6, nil, "target-ip:", split[csv_target_ip], "response-ip:", split[csv_response_ip])
		// add to resolver map
		key := Resolver_key{resolver_ip: split[csv_response_ip]}
		resolver_entry, ok := tester.resolver_data[key]
		if !ok {
			tester.resolver_data[key] = &Resolver_entry{
				resolver_ip:  net.ParseIP(split[csv_response_ip]),
				tfwd_ips:     make([]net.IP, 0),
				rate_pos:     0,
				rate_limiter: rate.NewLimiter(rate.Every(time.Duration(1000000/tester.rate_curve[0])*time.Microsecond), 1),
				answer_data:  make([]Answer_entry, 0),
			}
			resolver_entry = tester.resolver_data[key]
		}
		resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, net.ParseIP(split[csv_target_ip]))
	}

	logging.Println(6, nil, "read all lines")
	logging.Println(3, nil, "there are", len(tester.resolver_data), "resolvers")
}

func (tester *Rate_tester) rate_test_target(id int, entry *Resolver_entry) {
	// create a dns query
	var dnsid uint16 = 0
	for {
		t_start := time.Now().UnixMicro()
		// send for increate_interval ms
		for time.Now().UnixMicro()-t_start < int64(tester.increase_interval)*1000 {
			var query_domain string
			if config.Cfg.Dynamic_domain {
				hash := sha256.New()
				time_bytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(time_bytes, (uint64)(time.Now().UnixMicro()))
				hash.Write(time_bytes)
				domain_prefix := hex.EncodeToString(hash.Sum(nil)[0:4])
				query_domain = domain_prefix + "." + config.Cfg.Dns_query
				logging.Println(6, "Sender "+strconv.Itoa(id), "using query domain:", query_domain)
			} else {
				query_domain = config.Cfg.Dns_query
			}
			//TODO check if ip on blocklist
			// entry.tfwd_ips[entry.tfwd_pool_pos]
			logging.Println(6, "Sender "+strconv.Itoa(id), "sending dns to", entry.tfwd_ips[entry.tfwd_pool_pos].String(), ", resolver", entry.resolver_ip.String())
			tester.Send_udp_pkt(tester.Build_dns(entry.tfwd_ips[entry.tfwd_pool_pos], layers.UDPPort(entry.outport), dnsid, query_domain))
			dnsid++
			entry.tfwd_pool_pos = (entry.tfwd_pool_pos + 1) % len(entry.tfwd_ips)
			r := entry.rate_limiter.Reserve()
			if !r.OK() {
				log.Println("Rate limit exceeded")
			}
			time.Sleep(r.Delay())
		}
		entry.calc_last_second_rate(tester)
		logging.Println(5, "Sender "+strconv.Itoa(id), "last calculated rate is ", entry.moving_avg_rate)
		// set rate limiter to next value
		if entry.rate_pos == len(tester.rate_curve)-1 {
			logging.Println(5, "Sender "+strconv.Itoa(id), "rate curve exhausted")
			break
		}
		if entry.moving_avg_rate < tester.rec_thres*float64(tester.rate_curve[entry.rate_pos]) {
			logging.Println(5, "Sender "+strconv.Itoa(id), "receiving rate too small, quitting")
			break
		}
		entry.rate_pos++
		logging.Println(5, "Sender "+strconv.Itoa(id), "rate up", tester.rate_curve[entry.rate_pos], "Pkts/s")
		entry.rate_limiter.SetLimit(rate.Every(time.Duration(1000000/tester.rate_curve[entry.rate_pos]) * time.Microsecond))
	}
	// calc final rate
	entry.calc_last_second_rate(tester)
	logging.Println(4, "Sender "+strconv.Itoa(id), "final avg rate for ", entry.resolver_ip, "is", entry.moving_avg_rate, "Pkts/s")
	logging.Println(4, "Sender "+strconv.Itoa(id), "max rate for ", entry.resolver_ip, "is", entry.max_rate, "Pkts/s")
	// TODO test stability at max rate
}

func (tester *Rate_tester) send_packets(id int) {
	defer tester.sender_wg.Done()
	for {
		tester.resolver_mu.Lock()
		if len(tester.resolver_data) == 0 {
			tester.resolver_mu.Unlock()
			logging.Println(4, "Sender "+strconv.Itoa(id), "list exhausted, returning")
			return
		}
		// retrieve the next resolver from the map
		var key Resolver_key
		for key = range tester.resolver_data { // pseudo-random key, TODO how random is this?
			break
		}
		entry := tester.resolver_data[key]
		delete(tester.resolver_data, key)
		outport := tester.current_port
		entry.outport = (uint16)(outport)
		tester.current_port++
		if tester.current_port > uint32(config.Cfg.Port_max) {
			tester.current_port = uint32(config.Cfg.Port_min)
		}
		act_key := Active_key{port: uint16(outport)}
		tester.active_resolvers[act_key] = entry
		tester.resolver_counter++
		tester.resolver_mu.Unlock()
		logging.Println(4, "Sender "+strconv.Itoa(id), "rate limit testing resolver", tester.resolver_counter, entry.resolver_ip, "on port", outport)
		// === start the rate limit testing to that target ===
		tester.rate_test_target(id, entry)
		tester.finished_resolvers <- entry
		tester.resolver_mu.Lock()
		delete(tester.active_resolvers, act_key)
		tester.resolver_mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
}

func (tester *Rate_tester) Handle_pkt(pkt gopacket.Packet) {
	rec_time := time.Now().UnixMicro()
	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	_, ok := ip_layer.(*layers.IPv4)
	if !ok {
		return
	}

	udp_layer := pkt.Layer(layers.LayerTypeUDP)
	if udp_layer == nil {
		return
	}
	udp, ok := udp_layer.(*layers.UDP)
	if !ok { // skip wrong packets
		return
	}
	// pkts w/o content will be dropped
	if pkt.ApplicationLayer() == nil {
		return
	}

	logging.Println(6, nil, "received data")
	// decode as DNS Packet
	dns := &layers.DNS{}
	pld := udp.LayerPayload()
	err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
	if err != nil {
		logging.Println(5, nil, "DNS not found")
		return
	}
	logging.Println(6, nil, "got DNS response")
	// check if item in map and assign value
	tester.resolver_mu.Lock()
	rate_entry, ok := tester.active_resolvers[Active_key{port: uint16(udp.DstPort)}]
	tester.resolver_mu.Unlock()
	if !ok {
		logging.Println(6, nil, "got DNS but cant find related resolver")
		return
	}
	rate_entry.answer_mu.Lock()
	ans_entry := Answer_entry{
		ts:               rec_time,
		dns_payload_size: len(pld),
	}
	rate_entry.answer_data = append(rate_entry.answer_data, ans_entry)
	rate_entry.answer_mu.Unlock()
}

func (tester *Rate_tester) Start_ratetest(args []string, outpath string) {
	tester.increase_interval = 2000 // ms
	tester.resolver_data = make(map[Resolver_key]*Resolver_entry)
	tester.active_resolvers = make(map[Active_key]*Resolver_entry)
	// load rate curve from config
	// the rate will increase over time up to a maximum value
	var rate_values []string = strings.Split(config.Cfg.Rate_curve, ",")
	tester.rate_curve = make([]int, 0)
	for _, rate_value := range rate_values {
		rate_val_int, err := strconv.Atoi(strings.Trim(rate_value, " "))
		if err != nil {
			logging.Println(1, nil, "cannot convert value in rate curve to int")
			return
		}
		tester.rate_curve = append(tester.rate_curve, rate_val_int)
	}
	logging.Println(4, nil, "rate curve:", tester.rate_curve)
	tester.current_port = uint32(config.Cfg.Port_min)
	tester.rec_thres = 0.75
	tester.L2_sender = &tester.L2
	tester.Base_methods = tester
	tester.finished_resolvers = make(chan *Resolver_entry, 128)

	tester.Sender_init()
	tester.Base_init()
	tester.Bind_ports()

	if len(args) < 1 {
		logging.Println(1, nil, "missing intersect input file")
	}
	tester.Read_forwarders(args[0])

	// packet capture will call Handle_pkt
	handle := common.Get_ether_handle("udp")
	tester.Wg.Add(1)
	go tester.Packet_capture(handle)
	// path to an output directory, each resolver will be written to its own file
	go tester.write_results(outpath)
	// start ratelimit senders
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		tester.sender_wg.Add(1)
		go tester.send_packets(i)
	}
	tester.sender_wg.Wait()
	logging.Println(3, nil, "Sending completed")

	time.Sleep(5 * time.Second)
	close(tester.Stop_chan)
	handle.Close()

	tester.Wg.Wait()
	tester.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
