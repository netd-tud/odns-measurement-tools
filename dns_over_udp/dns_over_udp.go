package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/ilyakaznacheev/cleanenv"

	"golang.org/x/net/ipv4"

	"github.com/breml/bpfutils"
	"golang.org/x/time/rate"
)

const (
	debug = true
)

// config
type cfg_db struct {
	Iface_name     string `yaml:"iface_name"`
	Iface_ip       string `yaml:"iface_ip"`
	Dst_port       uint16 `yaml:"dst_port"`
	Port_min       uint16 `yaml:"port_min"`
	Port_max       uint16 `yaml:"port_max"`
	Dns_query      string `yaml:"dns_query"`
	Excl_ips_fname string `yaml:"exclude_ips_fname"`
	Pkts_per_sec   int    `yaml:"pkts_per_sec"`
}

var cfg cfg_db

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

var blocked_nets []*net.IPNet = []*net.IPNet{}

var send_limiter *rate.Limiter

var DNS_PAYLOAD_SIZE uint16

var waiting_to_end = false

// slice for sockets that will be bound on program start
var bound_sockets = []*net.UDPConn{}

// this struct contains all relevant data to track the dns query & response
type scan_data_item struct {
	id       uint32
	ts       time.Time
	ip       net.IP
	answerip net.IP
	port     layers.UDPPort
	dnsid    uint16
	dns_recs []net.IP
}

// key for the map below
type scan_item_key struct {
	port  layers.UDPPort
	dnsid uint16
}

// map to track udp communication, key is a tuple of (port, dnsid)
type root_scan_data struct {
	mu    sync.Mutex
	items map[scan_item_key]*scan_data_item
}

var scan_data root_scan_data = root_scan_data{
	items: make(map[scan_item_key]*scan_data_item),
}

var write_chan = make(chan *scan_data_item, 4096)

func scan_item_to_strarr(scan_item *scan_data_item) []string {
	// csv format: id;target_ip;response_ip;arecords;timestamp;port;dnsid
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.id)))
	record = append(record, scan_item.ip.String())
	record = append(record, scan_item.answerip.String())
	record = append(record, scan_item.ts.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.port.String())
	record = append(record, strconv.Itoa((int)(scan_item.dnsid)))
	dns_answers := ""
	for i, dns_ip := range scan_item.dns_recs {
		dns_answers += dns_ip.String()
		if i != len(scan_item.dns_recs)-1 {
			dns_answers += ","
		}
	}
	record = append(record, dns_answers)
	return record
}

func write_results() {
	defer wg.Done()
	csvfile, err := os.Create("udp_results.csv.gz")
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Close()

	writer := csv.NewWriter(zip_writer)
	writer.Comma = ';'
	defer writer.Flush()

	for {
		select {
		case scan_item := <-write_chan:
			writer.Write(scan_item_to_strarr(scan_item))
			// remove entry from map
			scan_data.mu.Lock()
			delete(scan_data.items, scan_item_key{scan_item.port, scan_item.dnsid})
			scan_data.mu.Unlock()
		case <-stop_chan:
			return
		}
	}
}

// periodically remove items that get no response from map
func timeout() {
	defer wg.Done()
	for {
		select {
		case <-time.After(1 * time.Second):
			//go through map's keyset
			scan_data.mu.Lock()
			for k, v := range scan_data.items {
				//remove each key where its timestamp is older than x seconds
				if time.Now().Unix()-v.ts.Unix() > 20 {
					delete(scan_data.items, k)
				}
			}
			scan_data.mu.Unlock()
		case <-stop_chan:
			return
		}
	}
}

var opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func send_udp_pkt(ip layers.IPv4, udp layers.UDP, payload []byte) {
	ip_head_buf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ip_head_buf, opts)
	if err != nil {
		panic(err)
	}
	ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
	if err != nil {
		panic(err)
	}

	udp_buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(udp_buf, opts, &udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	if err = raw_con.WriteTo(ip_head, udp_buf.Bytes(), nil); err != nil {
		panic(err)
	}
}

func build_dns(dst_ip net.IP, src_port layers.UDPPort, dnsid uint16) (layers.IPv4, layers.UDP, []byte) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolUDP,
		Id:       1,
	}

	// Create udp layer
	udp := layers.UDP{
		SrcPort: src_port,
		DstPort: layers.UDPPort(cfg.Dst_port),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	// create dns layers
	qst := layers.DNSQuestion{
		Name:  []byte(cfg.Dns_query),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	dns := layers.DNS{
		Questions: []layers.DNSQuestion{qst},
		RD:        true,
		QDCount:   1,
		OpCode:    layers.DNSOpCodeQuery,
		ID:        dnsid,
	}

	dns_buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(dns_buf, gopacket.SerializeOptions{}, &dns)
	return ip, udp, dns_buf.Bytes()
}

func send_dns(id uint32, dst_ip net.IP, src_port layers.UDPPort, dnsid uint16) {
	// generate sequence number based on the first 21 bits of the hash
	if debug {
		log.Println(dst_ip, "port=", src_port, "dnsid=", dnsid)
	}
	// check for sequence number collisions
	scan_data.mu.Lock()
	s_d_item := scan_data_item{
		id:       id,
		ts:       time.Now(),
		ip:       dst_ip,
		port:     src_port,
		dns_recs: nil,
	}
	if debug {
		log.Println("scan_data=", s_d_item)
	}
	scan_data.items[scan_item_key{src_port, dnsid}] = &s_d_item
	scan_data.mu.Unlock()

	send_udp_pkt(build_dns(dst_ip, src_port, dnsid))
}

func handle_pkt(pkt gopacket.Packet) {
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
		if debug {
			log.Println("received data")
		}
		// decode as DNS Packet
		dns := &layers.DNS{}
		pld := udp.LayerPayload()
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			if debug {
				log.Println("DNS not found")
			}
			return
		}
		if debug {
			log.Println("got DNS response")
		}
		// check if item in map and assign value
		scan_data.mu.Lock()
		scan_item, ok := scan_data.items[scan_item_key{udp.DstPort, dns.ID}]
		scan_data.mu.Unlock()
		if !ok {
			return
		}
		answers := dns.Answers
		var answers_ip []net.IP
		for _, answer := range answers {
			if answer.IP != nil {
				answers_ip = append(answers_ip, answer.IP)
				if debug {
					log.Println(answer.IP)
				}
			} else {
				if debug {
					log.Println("non IP type found in answer")
				}
				//return
			}
		}
		scan_item.answerip = ip.SrcIP
		scan_item.dns_recs = answers_ip
		// queue for writeout
		write_chan <- scan_item
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
			go handle_pkt(pkt)
		case <-stop_chan:
			if debug {
				log.Println("stopping packet capture")
			}
			return
		}
	}
}

// lockable datastructure for the init phase
type synced_init struct {
	mu    sync.Mutex
	id    uint32
	port  uint16
	dnsid uint16
}

// synced between multiple init_udp()
var ip_loop_id synced_init = synced_init{
	id:    0,
	port:  61440,
	dnsid: 0,
}

func update_sync_init() (uint32, uint16, uint16) {
	ip_loop_id.mu.Lock()
	defer ip_loop_id.mu.Unlock()
	ip_loop_id.id += 1
	if (uint32)(ip_loop_id.dnsid)+1 > 0xFFFF {
		ip_loop_id.dnsid = 0
		// restart at the beginning of the port range
		if (uint32)(ip_loop_id.port)+1 > (uint32)(cfg.Port_max) {
			ip_loop_id.port = cfg.Port_min
		} else {
			ip_loop_id.port += 1
		}
	} else {
		ip_loop_id.dnsid += 1
	}
	return ip_loop_id.id, ip_loop_id.port, ip_loop_id.dnsid
}

func init_udp(port_min uint16, port_max uint16) {
	defer wg.Done()
	for {
		select {
		case dst_ip := <-ip_chan:
			// check if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				if debug {
					log.Println("excluding ip:", dst_ip)
				}
				continue
			}
			id, src_port, dns_id := update_sync_init()
			if debug {
				log.Println("ip:", dst_ip, "id=", id, "port=", src_port, "dns_id=", dns_id)
			}
			r := send_limiter.Reserve()
			if !r.OK() {
				log.Println("Rate limit exceeded")
			}
			time.Sleep(r.Delay())
			send_dns(id, dst_ip, layers.UDPPort(src_port), dns_id)
		case <-stop_chan:
			return
		}
	}
}

func read_ips_file(fname string) {
	defer wg.Done()
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ip_chan <- net.ParseIP(line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	if debug {
		log.Println("read all ips, waiting to end ...")
	}
	waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(stop_chan)
}

func close_handle(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	<-stop_chan
	if debug {
		log.Println("closing handle")
	}
	handle.Close()
	if debug {
		log.Println("handle closed")
	}
}

func load_config() {
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		panic(err)
	}
	if debug {
		log.Println("config:", cfg)
	}
}

func write_to_log(msg string) {
	logfile, err := os.OpenFile("run.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer logfile.Close()
	logfile.WriteString(msg + "\n")
}

// Linear Congruential Generator
// as described in https://stackoverflow.com/a/53551417
type lcg_state struct {
	value      int
	offset     int
	multiplier int
	modulus    int
	max        int
	found      int
}

var lcg_ipv4 lcg_state

func (lcg *lcg_state) init(stop int) {
	// Seed range with a random integer.
	lcg.value = rand.Intn(stop)
	lcg.offset = rand.Intn(stop)*2 + 1                                  // Pick a random odd-valued offset.
	lcg.multiplier = 4*(int(stop/4)) + 1                                // Pick a multiplier 1 greater than a multiple of 4
	lcg.modulus = int(math.Pow(2, math.Ceil(math.Log2(float64(stop))))) // Pick a modulus just big enough to generate all numbers (power of 2)
	lcg.found = 0                                                       // Track how many random numbers have been returned
	lcg.max = stop
}

func (lcg *lcg_state) next() int {
	for lcg.value >= lcg.max {
		lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	}
	lcg.found += 1
	value := lcg.value
	// Calculate the next value in the sequence.
	lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	return value
}

func (lcg *lcg_state) has_next() bool {
	return lcg.found < lcg.max
}

func ip42uint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint322ip(ipint uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipint)
	return ip
}

func gen_ips(netip net.IP, hostsize int) {
	defer wg.Done()
	netip_int := ip42uint32(netip)
	lcg_ipv4.init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.has_next() {
		select {
		case <-stop_chan:
			return
		default:
			val := lcg_ipv4.next()
			ip_chan <- uint322ip(netip_int + uint32(val))
		}
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just generated before ending the program
	if debug {
		log.Println("all ips generated, waiting to end ...")
	}
	waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(stop_chan)
}

func exclude_ips() {
	if _, err := os.Stat(cfg.Excl_ips_fname); errors.Is(err, os.ErrNotExist) {
		if debug {
			log.Println("ip exclusion list not found, skipping")
			log.Println("exclusion list filename was read as:", cfg.Excl_ips_fname)
		}
		return
	}
	file, err := os.Open(cfg.Excl_ips_fname)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		comment_pos := strings.IndexByte(line, '#')
		if comment_pos == -1 {
			comment_pos = len(line)
		}
		pos_net := line[:comment_pos]
		pos_net = strings.TrimSpace(pos_net)
		if pos_net == "" {
			continue
		}
		_, new_net, err := net.ParseCIDR(pos_net)
		if err != nil { // if there are errors try if the string maybe is a single ip
			toblock_ip := net.ParseIP(pos_net)
			if toblock_ip == nil {
				log.Println("could not interpret line, skipping")
				continue
			}
			mask := net.CIDRMask(32, 32) // 32 bits for IPv4
			new_net = &net.IPNet{IP: toblock_ip, Mask: mask}
		}

		blocked_nets = append(blocked_nets, new_net)
		if debug {
			log.Println("added blocked net:", new_net.String())
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

// binding all the sockets potentially in use by the scanner
// so no icmp port unreachable is sent and no other application
// may use these ports by chance
func bind_ports() {
	if debug {
		log.Println("Binding ports")
	}
	var port uint32
	for port = (uint32)(cfg.Port_min); port <= (uint32)(cfg.Port_max); port++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.ParseIP(cfg.Iface_ip),
			Port: (int)(port),
		})
		if err != nil {
			if debug {
				log.Println("Could not bind to UDP port", port)
				log.Println("reason:", err)
			}
			// TODO should then probably exclude these from the scan
		} else {
			bound_sockets = append(bound_sockets, conn)
		}
	}
}

func unbind_ports() {
	if debug {
		log.Println("Unbinding ports")
	}
	for _, sock := range bound_sockets {
		sock.Close()
	}
}

func main() {
	// before running disable icmp unreachable msgs
	// sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

	// write start ts to log
	write_to_log("START " + time.Now().UTC().String())
	// command line args
	if len(os.Args) < 2 {
		write_to_log("END " + time.Now().UTC().String() + " arg not given")
		if debug {
			log.Println("ERR need filename or net in CIDR notation")
		}
		return
	}
	ip_or_file_split := strings.Split(os.Args[1], "/")
	var fname string
	var netip net.IP
	var hostsize int
	if len(ip_or_file_split) == 1 {
		// using filename
		fname = ip_or_file_split[0]
	} else if len(ip_or_file_split) == 2 {
		// using CIDR net
		netip = net.ParseIP(ip_or_file_split[0])
		var err error
		hostsize, err = strconv.Atoi(ip_or_file_split[1])
		if err != nil {
			panic(err)
		}
		hostsize = 32 - hostsize
	} else {
		write_to_log("END " + time.Now().UTC().String() + " wrongly formatted input arg")
		if debug {
			log.Println("ERR check your input arg (filename or CIDR notation)")
		}
	}

	// handle ctrl+c SIGINT
	go func() {
		interrupt_chan := make(chan os.Signal, 1)
		signal.Notify(interrupt_chan, os.Interrupt)
		<-interrupt_chan
		if waiting_to_end {
			if debug {
				log.Println("already ending")
			}
		} else {
			if debug {
				log.Println("received SIGINT, ending")
			}
			close(stop_chan)
		}
	}()

	load_config()
	exclude_ips()
	bind_ports()
	send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/cfg.Pkts_per_sec)*time.Microsecond), 1)
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := build_dns(net.ParseIP("0.0.0.0"), 0, 0)
	DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
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
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, fmt.Sprint("udp and ip dst ", cfg.Iface_ip, " and src port ", cfg.Dst_port))
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err = net.ListenPacket("ip4:udp", cfg.Iface_ip)
	if err != nil {
		panic(err)
	}
	raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}

	// start packet capture as goroutine
	wg.Add(5)
	go packet_capture(handle)
	go write_results()
	go timeout()
	if fname != "" {
		if debug {
			log.Println("running in filename mode, this will not be randomized, the ips are probed as listed in the file")
		}
		go read_ips_file(fname)
	} else {
		if debug {
			log.Println("running in CIDR mode")
		}
		go gen_ips(netip, hostsize)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go init_udp(cfg.Port_min, cfg.Port_max)
	}
	go close_handle(handle)
	wg.Wait()
	unbind_ports()
	if debug {
		log.Println("all routines finished")
	}
	write_to_log("END " + time.Now().UTC().String())
	if debug {
		log.Println("program done")
	}
}
