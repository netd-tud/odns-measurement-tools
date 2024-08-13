package udpscanner

import (
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
	"dns_tools/scanner"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Udp_scanner struct {
	scanner.Base_scanner
	udp_common.Udp_sender
	udp_common.Udp_binder
	// slice for sockets that will be bound on program start
	bound_sockets []*net.UDPConn
	ip_loop_id    synced_init
}

// lockable datastructure for the init phase
type synced_init struct {
	mu    sync.Mutex
	id    uint32
	port  uint16
	dnsid uint16
}

func (udps *Udp_scanner) update_sync_init() (uint32, uint16, uint16) {
	udps.ip_loop_id.mu.Lock()
	defer udps.ip_loop_id.mu.Unlock()
	udps.ip_loop_id.id += 1
	if (uint32)(udps.ip_loop_id.dnsid)+1 > 0xFFFF {
		udps.ip_loop_id.dnsid = 0
		// restart at the beginning of the port range
		if (uint32)(udps.ip_loop_id.port)+1 > (uint32)(config.Cfg.Port_max) {
			udps.ip_loop_id.port = config.Cfg.Port_min
		} else {
			udps.ip_loop_id.port += 1
		}
	} else {
		udps.ip_loop_id.dnsid += 1
	}
	return udps.ip_loop_id.id, udps.ip_loop_id.port, udps.ip_loop_id.dnsid
}

// this struct contains all relevant data to track the dns query & response
type udp_scan_data_item struct {
	id       uint32
	ts       time.Time
	ip       net.IP
	answerip net.IP
	port     layers.UDPPort
	dnsid    uint16
	dns_recs []net.IP
}

func (u *udp_scan_data_item) Get_timestamp() time.Time {
	return u.ts
}

// key for the map below
type udp_scan_item_key struct {
	port  layers.UDPPort
	dnsid uint16
}

func (udps *Udp_scanner) Write_item(scan_item *scanner.Scan_data_item) {
	udp_scan_item, ok := (*scan_item).(*udp_scan_data_item)
	if !ok {
		return
	}
	udps.Writer.Write(scan_item_to_strarr(udp_scan_item))
	// remove entry from map
	udps.Scan_data.Mu.Lock()
	delete(udps.Scan_data.Items, udp_scan_item_key{udp_scan_item.port, udp_scan_item.dnsid})
	udps.Scan_data.Mu.Unlock()
}

func scan_item_to_strarr(scan_item *udp_scan_data_item) []string {
	// csv format: id;target_ip;response_ip;arecords;timestamp;port;dnsid
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.id)))
	record = append(record, scan_item.ip.String())
	record = append(record, scan_item.answerip.String())
	dns_answers := ""
	for i, dns_ip := range scan_item.dns_recs {
		dns_answers += dns_ip.String()
		if i != len(scan_item.dns_recs)-1 {
			dns_answers += ","
		}
	}
	record = append(record, dns_answers)
	record = append(record, scan_item.ts.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.port.String())
	record = append(record, strconv.Itoa((int)(scan_item.dnsid)))
	return record
}

func (udps *Udp_scanner) send_dns(id uint32, dst_ip net.IP, src_port layers.UDPPort, dnsid uint16) {
	// generate sequence number based on the first 21 bits of the hash
	logging.Println(6, nil, dst_ip, "port=", src_port, "dnsid=", dnsid)
	// check for sequence number collisions
	udps.Scan_data.Mu.Lock()
	s_d_item := udp_scan_data_item{
		id:       id,
		ts:       time.Now(),
		ip:       dst_ip,
		port:     src_port,
		dns_recs: nil,
		dnsid:    dnsid,
	}
	logging.Println(6, nil, "scan_data=", s_d_item)
	udps.Scan_data.Items[udp_scan_item_key{src_port, dnsid}] = &s_d_item
	udps.Scan_data.Mu.Unlock()

	udps.Send_udp_pkt(udps.Build_dns(dst_ip, src_port, dnsid, config.Cfg.Dns_query))
}

func (udps *Udp_scanner) Handle_pkt(pkt gopacket.Packet) {
	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	ip, ok := ip_layer.(*layers.IPv4)
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
	if pkt.ApplicationLayer() != nil {
		logging.Println(5, nil, "received data")
		// decode as DNS Packet
		dns := &layers.DNS{}
		pld := udp.LayerPayload()
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			logging.Println(5, nil, "DNS not found")
			return
		}
		logging.Println(5, nil, "got DNS response")
		// check if item in map and assign value
		udps.Scan_data.Mu.Lock()
		scan_item, ok := udps.Scan_data.Items[udp_scan_item_key{udp.DstPort, dns.ID}]
		udps.Scan_data.Mu.Unlock()
		if !ok {
			return
		}
		udp_scan_item, ok := scan_item.(*udp_scan_data_item)
		if !ok {
			log.Fatal("cast failed, wrong type")
		}
		answers := dns.Answers
		var answers_ip []net.IP
		for _, answer := range answers {
			if answer.IP != nil {
				answers_ip = append(answers_ip, answer.IP)
				logging.Println(5, nil, "answer ip:", answer.IP)
			} else {
				logging.Println(5, nil, "non IP type found in answer")
				//return
			}
		}
		udp_scan_item.answerip = ip.SrcIP
		udp_scan_item.dns_recs = answers_ip
		// queue for writeout
		udps.Write_chan <- &scan_item
	}
}

func (udps *Udp_scanner) init_udp() {
	defer udps.Wg.Done()
	for {
		select {
		case dst_ip := <-udps.Ip_chan:
			// check if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range udps.Blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				logging.Println(4, nil, "excluding ip:", dst_ip)
				continue
			}
			id, src_port, dns_id := udps.update_sync_init()
			logging.Println(5, nil, "ip:", dst_ip, "id=", id, "port=", src_port, "dns_id=", dns_id)
			if config.Cfg.Pkts_per_sec > 0 {
				r := udps.Send_limiter.Reserve()
				if !r.OK() {
					log.Println("Rate limit exceeded")
				}
				time.Sleep(r.Delay())
			}
			udps.send_dns(id, dst_ip, layers.UDPPort(src_port), dns_id)
		case <-udps.Stop_chan:
			return
		}
	}
}

func (udps *Udp_scanner) gen_ips(netip net.IP, hostsize int) {
	defer udps.Wg.Done()
	netip_int := generator.Ip42uint32(netip)
	var lcg_ipv4 generator.Lcg
	lcg_ipv4.Init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.Has_next() {
		select {
		case <-udps.Stop_chan:
			return
		default:
			val := lcg_ipv4.Next()
			udps.Ip_chan <- generator.Uint322ip(netip_int + uint32(val))
		}
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just generated before ending the program
	var wait_time int = len(udps.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, nil, "all ips generated, waiting", wait_time, "seconds to end")
	udps.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(udps.Stop_chan)
}

func (udps *Udp_scanner) Start_scan(args []string, outpath string) {
	udps.Scanner_init()
	udps.Sender_init()
	udps.L2_sender = &udps.L2
	udps.Scanner_methods = udps
	udps.Base_methods = udps
	udps.bound_sockets = []*net.UDPConn{}
	// synced between multiple init_udp()
	udps.ip_loop_id = synced_init{
		id:    0,
		port:  config.Cfg.Port_min,
		dnsid: 0,
	}

	// write start ts to log
	logging.Write_to_runlog("START " + time.Now().UTC().String())
	// command line args
	if len(os.Args) < 2 {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " arg not given")
		logging.Println(1, nil, "ERR need filename or net in CIDR notation")
		return
	}
	var fname string
	var netip net.IP
	var hostsize int
	fname, netip, hostsize = udps.Get_cidr_filename(args[0])

	udps.Bind_ports()
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := udps.Build_dns(net.ParseIP("0.0.0.0"), 0, 0, config.Cfg.Dns_query)
	udps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle("udp")
	// start packet capture as goroutine
	udps.Wg.Add(5)
	go udps.Packet_capture(handle)
	go udps.Write_results(outpath)
	go udps.Timeout()
	if fname != "" {
		logging.Println(3, nil, "running in filename mode")
		go udps.Read_ips_file(fname)
	} else {
		logging.Println(3, nil, "running in CIDR mode")
		go udps.gen_ips(netip, hostsize)
	}
	for i := 0; i < 8; i++ {
		udps.Wg.Add(1)
		go udps.init_udp()
	}
	go udps.Close_handle(handle)
	udps.Wg.Wait()
	udps.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
