package tcpscanner

import (
	"dns_tools/common"
	"dns_tools/common/tcp_common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
	"dns_tools/scanner"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Tcp_scanner struct {
	scanner.Base_scanner
	tcp_common.Tcp_sender
}

/*	id:
*	(seq-num)		(Ports from 61440)   	(2048 byte padding)
*	2^32	*			2^11			/			 2^11		=2^32
*
*	increment: |y=11*x | z=21*x|
*	seq_num = z*2^11, max:2^32-2^11
*	port = y+15<<15 = y+61440
 */

// this struct contains all relevant data to track the tcp connection
type tcp_scan_data_item struct {
	id       uint32
	ts       time.Time
	ip       net.IP
	port     layers.TCPPort
	seq      uint32
	ack      uint32
	flags    tcp_common.TCP_flags
	dns_recs []net.IP
	Next     *tcp_scan_data_item
}

func (t *tcp_scan_data_item) Get_timestamp() time.Time {
	return t.ts
}

func (item *tcp_scan_data_item) last() *tcp_scan_data_item {
	var cur *tcp_scan_data_item = item
	for cur.Next != nil {
		cur = cur.Next
	}
	return cur
}

// key for the map below
type tcp_scan_item_key struct {
	port layers.TCPPort
	seq  uint32
}

func (tcps *Tcp_scanner) Build_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) (layers.IPv4, layers.TCP, []byte) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(config.Cfg.Dst_port),
		ACK:     true,
		PSH:     true,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// create dns layers
	qst := layers.DNSQuestion{
		Name:  []byte(config.Cfg.Dns_query),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	dns := layers.DNS{
		Questions: []layers.DNSQuestion{qst},
		RD:        true,
		QDCount:   1,
		OpCode:    layers.DNSOpCodeQuery,
		ID:        uint16(rand.Intn(65536)),
	}

	dns_buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(dns_buf, gopacket.SerializeOptions{}, &dns)
	// prepend dns payload with its size, as gopacket does not do this automatically
	dns_buf_bytes := dns_buf.Bytes()
	dns_corrected := make([]byte, len(dns_buf_bytes)+2)
	dns_corrected[0] = uint8(0)
	dns_corrected[1] = uint8(len(dns_buf_bytes))
	for i := 0; i < len(dns_buf_bytes); i++ {
		dns_corrected[i+2] = dns_buf_bytes[i]
	}
	return ip, tcp, dns_corrected
}

func (tcps *Tcp_scanner) Send_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32) {
	tcps.Send_tcp_pkt(tcps.Build_ack_with_dns(dst_ip, src_port, seq_num, ack_num))
}

func scan_item_to_strarr(scan_item *tcp_scan_data_item) []string {
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.id)))
	record = append(record, scan_item.ts.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.ip.String())
	record = append(record, scan_item.port.String())
	record = append(record, strconv.Itoa(int(scan_item.seq)))
	record = append(record, strconv.Itoa(int(scan_item.ack)))
	var flags string
	if scan_item.flags.SYN {
		flags += "S"
	}
	if scan_item.flags.RST {
		flags += "R"
	}
	if scan_item.flags.FIN {
		flags += "F"
	}
	if scan_item.flags.PSH {
		flags += "P"
	}
	if scan_item.flags.ACK {
		flags += "A"
	}
	record = append(record, flags)
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

func (tcps *Tcp_scanner) Write_item(root_item *scanner.Scan_data_item) {
	tcp_root_item, ok := (*root_item).(*tcp_scan_data_item)
	if !ok {
		return
	}
	scan_item := tcp_root_item

	for scan_item != nil {
		tcps.Writer.Write(scan_item_to_strarr(scan_item))
		scan_item = scan_item.Next
	}
	// remove entry from map
	tcps.Scan_data.Mu.Lock()
	delete(tcps.Scan_data.Items, tcp_scan_item_key{tcp_root_item.port, tcp_root_item.seq})
	tcps.Scan_data.Mu.Unlock()
}

func (tcps *Tcp_scanner) Handle_pkt(ip *layers.IPv4, pkt gopacket.Packet) {
	tcp_layer := pkt.Layer(layers.LayerTypeTCP)
	if tcp_layer == nil {
		return
	}
	tcp_l, ok := tcp_layer.(*layers.TCP)
	if !ok { // skip wrong packets
		return
	}
	tcpflags := tcp_common.TCP_flags{
		PSH: tcp_l.PSH,
		FIN: tcp_l.FIN,
		SYN: tcp_l.SYN,
		RST: tcp_l.RST,
		ACK: tcp_l.ACK,
	}
	if pkt.ApplicationLayer() == nil {
		// SYN-ACK
		if tcpflags.Is_SYN_ACK() {
			logging.Println(5, nil, "received SYN-ACK")
			// check if item in map and assign value
			tcps.Scan_data.Mu.Lock()
			_root_data_item, ok := tcps.Scan_data.Items[tcp_scan_item_key{tcp_l.DstPort, tcp_l.Ack - 1}]
			tcps.Scan_data.Mu.Unlock()
			if !ok {
				return
			}
			tcp_root_data_item, ok := _root_data_item.(*tcp_scan_data_item)
			if !ok {
				log.Fatal("cast failed, wrong type")
			}
			last_data_item := tcp_root_data_item.last()
			// this should not occur, this would be the case if a syn-ack is being received more than once
			if last_data_item != tcp_root_data_item {
				return
			}
			data := tcp_scan_data_item{
				id:   last_data_item.id,
				ts:   time.Now(),
				port: tcp_l.DstPort,
				seq:  tcp_l.Seq,
				ack:  tcp_l.Ack,
				ip:   ip.SrcIP,
				flags: tcp_common.TCP_flags{
					FIN: tcp_l.FIN,
					SYN: tcp_l.SYN,
					RST: tcp_l.RST,
					PSH: tcp_l.PSH,
					ACK: tcp_l.ACK,
				},
			}
			last_data_item.Next = &data
			tcps.Send_ack_with_dns(tcp_root_data_item.ip, tcp_l.DstPort, tcp_l.Seq, tcp_l.Ack)
		} else
		// FIN-ACK
		if tcpflags.Is_FIN_ACK() {
			logging.Println(5, nil, "received FIN-ACK")
			tcps.Scan_data.Mu.Lock()
			_root_data_item, ok := tcps.Scan_data.Items[tcp_scan_item_key{tcp_l.DstPort, tcp_l.Ack - 2 - uint32(tcps.DNS_PAYLOAD_SIZE)}]
			tcps.Scan_data.Mu.Unlock()
			if !ok {
				return
			}
			tcp_root_data_item, ok := _root_data_item.(*tcp_scan_data_item)
			if !ok {
				log.Fatal("cast failed, wrong type")
			}

			last_data_item := tcp_root_data_item.last()
			if !(last_data_item.flags.Is_PSH_ACK()) {
				logging.Println(5, nil, "missing PSH-ACK, dropping")
				tcps.Send_ack_pos_fin(ip.SrcIP, tcp_l.DstPort, tcp_l.Seq, tcp_l.Ack, true)
				return
			}
			logging.Println(5, nil, "ACKing FIN-ACK")
			tcps.Send_ack_pos_fin(tcp_root_data_item.ip, tcp_l.DstPort, tcp_l.Seq, tcp_l.Ack, false)
			var switcheroo scanner.Scan_data_item = tcp_root_data_item
			tcps.Write_chan <- &switcheroo
		}
	} else
	// PSH-ACK || FIN-PSH-ACK == DNS Response
	if tcpflags.Is_PSH_ACK() || tcpflags.Is_FIN_PSH_ACK() {
		logging.Println(5, nil, "received PSH-ACK or FIN-PSH-ACK")
		// decode as DNS Packet
		dns := &layers.DNS{}
		// remove the first two bytes of the payload, i.e. size of the dns response
		// see build_ack_with_dns()
		if len(tcp_l.LayerPayload()) <= 2 {
			return
		}
		// validate payload size
		pld_size := int(tcp_l.LayerPayload()[0]) + int(tcp_l.LayerPayload()[1])<<8
		if pld_size == len(tcp_l.LayerPayload())-2 {
			return
		}
		pld := make([]byte, len(tcp_l.LayerPayload())-2)
		for i := 0; i < len(pld); i++ {
			pld[i] = tcp_l.LayerPayload()[i+2]
		}
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			logging.Println(5, nil, "DNS not found")
			return
		}
		logging.Println(4, nil, "got DNS response")
		// check if item in map and assign value
		tcps.Scan_data.Mu.Lock()
		_root_data_item, ok := tcps.Scan_data.Items[tcp_scan_item_key{tcp_l.DstPort, tcp_l.Ack - 1 - uint32(tcps.DNS_PAYLOAD_SIZE)}]
		tcps.Scan_data.Mu.Unlock()
		if !ok {
			return
		}
		tcp_root_data_item, ok := _root_data_item.(*tcp_scan_data_item)
		if !ok {
			log.Fatal("cast failed, wrong type")
		}
		last_data_item := tcp_root_data_item.last()
		// this should not occur, this would be the case if a psh-ack is being received more than once
		if last_data_item.flags.Is_PSH_ACK() {
			logging.Println(5, nil, "already received PSH-ACK")
			return
		}
		if !(last_data_item.flags.Is_SYN_ACK()) {
			logging.Println(5, nil, "missing SYN-ACK")
			return
		}
		answers := dns.Answers
		var answers_ip []net.IP
		for _, answer := range answers {
			if answer.IP != nil {
				answers_ip = append(answers_ip, answer.IP)
				logging.Println(6, nil, answer.IP)
			} else {
				logging.Println(5, nil, "non IP type found in answer")
				return
			}
		}
		data := tcp_scan_data_item{
			id:   last_data_item.id,
			ts:   time.Now(),
			port: tcp_l.DstPort,
			seq:  tcp_l.Seq,
			ack:  tcp_l.Ack,
			ip:   ip.SrcIP,
			flags: tcp_common.TCP_flags{
				FIN: tcp_l.FIN,
				SYN: tcp_l.SYN,
				RST: tcp_l.RST,
				PSH: tcp_l.PSH,
				ACK: tcp_l.ACK,
			},
			dns_recs: answers_ip,
		}
		last_data_item.Next = &data
		// send FIN-ACK to server
		tcps.Send_ack_pos_fin(tcp_root_data_item.ip, tcp_l.DstPort, tcp_l.Seq, tcp_l.Ack, true)
		// if this pkt is fin-psh-ack we will remove it from the map at this point already
		// because we wont receive any further fin-ack from the server
		if tcpflags.Is_FIN_PSH_ACK() {
			tcps.Write_chan <- &_root_data_item
		}
	}
}

func (tcps *Tcp_scanner) send_syn(id uint32, dst_ip net.IP) {
	// generate sequence number based on the first 21 bits of the id
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort((id >> 21) + 61440)
	logging.Println(6, nil, "sending syn to", dst_ip, "with seq_num=", seq)
	// check for sequence number collisions
	tcps.Scan_data.Mu.Lock()
	s_d_item := tcp_scan_data_item{
		id:   id,
		ts:   time.Now(),
		ip:   dst_ip,
		port: port,
		seq:  seq,
		ack:  0,
		flags: tcp_common.TCP_flags{
			FIN: false,
			ACK: false,
			RST: false,
			PSH: false,
			SYN: true,
		},
		dns_recs: nil,
		Next:     nil,
	}
	logging.Println(6, nil, "scan_data=", s_d_item)
	tcps.Scan_data.Items[tcp_scan_item_key{port, seq}] = &s_d_item
	tcps.Scan_data.Mu.Unlock()

	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: port,
		DstPort: 53,
		SYN:     true,
		Seq:     seq,
		Ack:     0,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	tcps.Send_tcp_pkt(ip, tcp, nil)
}

type u32id struct {
	mu sync.Mutex
	id uint32
}

// id for saving to results file, synced between multiple init_tcp()
var ip_loop_id u32id = u32id{
	id: 0,
}

func (tcps *Tcp_scanner) get_next_id() uint32 {
	ip_loop_id.mu.Lock()
	defer ip_loop_id.mu.Unlock()
	last_id := ip_loop_id.id
	ip_loop_id.id += 1
	return last_id
}

func (tcps *Tcp_scanner) init_tcp() {
	defer tcps.Wg.Done()
	for {
		select {
		case dst_ip := <-tcps.Ip_chan:
			// check if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range tcps.Blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				logging.Println(4, nil, "excluding ip:", dst_ip)
				continue
			}
			id := tcps.get_next_id()
			logging.Println(6, nil, "ip:", dst_ip, id)
			if config.Cfg.Pkts_per_sec > 0 {
				_ = tcps.Send_limiter.Take()
			}
			tcps.send_syn(id, dst_ip)
		case <-tcps.Stop_chan:
			return
		}
	}
}

func (tcps *Tcp_scanner) gen_ips(netip net.IP, hostsize int) {
	defer tcps.Wg.Done()
	netip_int := generator.Ip42uint32(netip)
	var lcg_ipv4 generator.Lcg
	lcg_ipv4.Init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.Has_next() {
		select {
		case <-tcps.Stop_chan:
			return
		default:
			val := lcg_ipv4.Next()
			tcps.Ip_chan <- generator.Uint322ip(netip_int + uint32(val))
		}
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	var wait_time int = len(tcps.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, nil, "all ips generated, waiting", wait_time, "seconds to end")
	tcps.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(tcps.Stop_chan)
}

func (tcps *Tcp_scanner) Start_scan(args []string, outpath string) {
	tcps.Scanner_init()
	tcps.Sender_init()
	tcps.L2_sender = &tcps.L2
	tcps.Scanner_methods = tcps
	tcps.Base_methods = tcps
	tcps.Set_iptable_rule()
	// write start ts to log
	logging.Write_to_runlog("START " + time.Now().UTC().String())
	// command line args
	if len(args) < 1 {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " arg not given")
		logging.Println(1, nil, "ERR need filename or net in CIDR notation")
		return
	}
	var fname string
	var netip net.IP
	var hostsize int
	fname, netip, hostsize = common.Get_cidr_filename(args[0])

	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := tcps.Build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0)
	tcps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle()
	// start packet capture as goroutine
	tcps.Wg.Add(5)
	go tcps.Packet_capture(handle)
	go tcps.Write_results(outpath)
	go tcps.Timeout()
	if fname != "" {
		logging.Println(3, nil, "running in filename mode")
		go tcps.Read_ips_file(fname)
	} else {
		logging.Println(3, nil, "running in CIDR mode")
		go tcps.gen_ips(netip, hostsize)
	}
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		tcps.Wg.Add(1)
		go tcps.init_tcp()
	}
	go tcps.Close_handle(handle)
	tcps.Wg.Wait()
	logging.Println(3, "Teardown", "all routines finished")
	tcps.Remove_iptable_rule()
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
