package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
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
	Verbosity      int    `yaml:"verbosity"`
}

var cfg cfg_db

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

// a simple struct for all the tcp flags needed
type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
}

// 0: OFF, 1: ERR, 2: WARN, 3: INFO, 4: DEBUG, 5: VERBOSE, 6: ALL
func println(lvl int, prefix interface{}, v ...any) {
	if lvl <= cfg.Verbosity {
		if prefix != "" {
			u := []any{}
			switch lvl {
			case 1:
				u = append(u, "ERR  ")
			case 2:
				u = append(u, "WARN ")
			case 3:
				u = append(u, "INFO ")
			case 4:
				fallthrough
			case 5:
				fallthrough
			case 6:
				u = append(u, "DEBUG")
			}
			u = append(u, "["+fmt.Sprintf("%v", prefix)+"]")
			u = append(u, v)
			v = u
		}
		log.Println(v...)
	}
}

func (flags TCP_flags) equals(tomatch TCP_flags) bool {
	return flags.FIN == tomatch.FIN &&
		flags.SYN == tomatch.SYN &&
		flags.RST == tomatch.RST &&
		flags.PSH == tomatch.PSH &&
		flags.ACK == tomatch.ACK
}

func (flags TCP_flags) is_PSH_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: false,
		RST: false,
		PSH: true,
		ACK: true,
	})
}

func (flags TCP_flags) is_SYN_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: true,
		RST: false,
		PSH: false,
		ACK: true,
	})
}

func (flags TCP_flags) is_SYN() bool {
	return flags.equals(TCP_flags{
		FIN: false,
		SYN: true,
		RST: false,
		PSH: false,
		ACK: false,
	})
}

func (flags TCP_flags) is_FIN_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: true,
		SYN: false,
		RST: false,
		PSH: false,
		ACK: true,
	})
}

func (flags TCP_flags) is_FIN_PSH_ACK() bool {
	return flags.equals(TCP_flags{
		FIN: true,
		SYN: false,
		RST: false,
		PSH: true,
		ACK: true,
	})
}

var DNS_PAYLOAD_SIZE uint16

var dns_traceroute_hop_counter = 0

var waiting_to_end = false

var lowest_port uint16 = 61024 // smallest multiple of 32 outside random port range

type tracert_param struct {
	active               sync.Mutex
	traceroute_mutex     sync.Mutex
	all_syns_sent        bool
	all_dns_packets_sent bool
	syn_ack_received     int64
	dns_reply_received   int64
	initial_ip           net.IP
	first_to_syn_ack     net.IP
}

func (param *tracert_param) zero() {
	param.all_dns_packets_sent = false
	param.all_syns_sent = false
	param.syn_ack_received = -1
	param.dns_reply_received = -1
}

var tracert_params = map[int]*tracert_param{}

var dns_traceroute_port = layers.TCPPort(10000)

var send_limiter *rate.Limiter

// this struct contains all relevant data to track the tcp connection
type scan_data_item struct {
	id       uint32
	ts       time.Time
	ip       net.IP
	port     layers.TCPPort
	seq      uint32
	ack      uint32
	flags    TCP_flags
	dns_recs []net.IP
	Next     *scan_data_item
}

func (item *scan_data_item) last() *scan_data_item {
	var cur *scan_data_item = item
	for cur.Next != nil {
		cur = cur.Next
	}
	return cur
}

// key for the map below
type scan_item_key struct {
	port layers.TCPPort
}

// map to track tcp connections, key is a port
type root_scan_data struct {
	mu    sync.Mutex
	items map[scan_item_key]*scan_data_item
}

var dns_icmp_data root_scan_data = root_scan_data{
	items: make(map[scan_item_key]*scan_data_item),
}

var opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func send_tcp_pkt(ip layers.IPv4, tcp layers.TCP, payload []byte) {
	ip_head_buf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ip_head_buf, opts)
	if err != nil {
		panic(err)
	}
	ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
	if err != nil {
		panic(err)
	}

	tcp_buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcp_buf, opts, &tcp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	if err = raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
		panic(err)
	}
}

func build_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, ttl uint8) (layers.IPv4, layers.TCP, []byte) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      ttl,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       uint16(calc_start_port(uint16(src_port))) + uint16(ttl),
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(cfg.Dst_port),
		ACK:     true,
		PSH:     true,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

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
		ID:        uint16(uint32(calc_start_port(uint16(src_port))) + uint32(ttl)),
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

func send_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, ttl uint8) {
	send_tcp_pkt(build_ack_with_dns(dst_ip, src_port, seq_num, ack_num, ttl))
}

func send_ack_pos_fin(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, fin bool) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(cfg.Dst_port),
		ACK:     true,
		FIN:     fin,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	send_tcp_pkt(ip, tcp, nil)
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
	icmp_layer := pkt.Layer(layers.LayerTypeICMPv4)
	icmp, _ := icmp_layer.(*layers.ICMPv4)
	if icmp != nil {
		println(5, "", "received ICMP packet")
		//icmpPacket, _ := icmp_layer.(*layers.ICMPv4)

		// Print information about the ICMPv4 packet
		//log.Println("IPv4 Source: ", ip.SrcIP)
		//log.Println("IPv4 Destination: ", ip.DstIP)

		// Extract the encapsulated TCP layer
		// The TCP layer is truncated, however, we only need the src port which is encoded in the first 2 bytes of the ip payload

		// get icmp payload bytes
		payloadBytes := icmp.LayerPayload()
		if payloadBytes == nil {
			return
		}
		//handle icmp payload as new ipv4 packet (Time Exceeded Message returns IP header + 8 bytes of ip payload)
		packet := gopacket.NewPacket(payloadBytes, layers.LayerTypeIPv4, gopacket.Default)

		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		if ip_layer == nil {
			// no tcp layer means not of interest to us!
			println(5, "", "No TCP layer found in the payload.")
			return
		}

		inner_ip, _ := ip_layer.(*layers.IPv4)
		// Decode source port (first 2 bytes)
		source_port := layers.TCPPort(binary.BigEndian.Uint16(inner_ip.Payload[:2]))
		start_port := calc_start_port(uint16(source_port))
		println(6, id_from_port(uint16(start_port)), "Source port: ", source_port)
		//log.Println("Destination Port:", tcp.DstPort)
		// Add more fields as needed

		params, exists := tracert_params[start_port]
		if !exists {
			// dont know where this packet came from but its not part of the scan
			println(5, id_from_port(uint16(start_port)), "traceroute parameters do not exist for start port", start_port)
			return
		}
		// if we did not receive a syn ack and the source port is <= 65100 (which we use for all the syns we sent) add this to the
		if params.syn_ack_received == -1 { //&& source_port >= 65000 && source_port < 65100 {
			src_port_int := int(source_port)
			hop := src_port_int - start_port
			if params.initial_ip.Equal(ip.SrcIP) {
				println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t Hop ", hop, " ", ip.SrcIP, "\033[0m")
			} else {
				println(3, id_from_port(uint16(start_port)), "[*] \t Hop ", hop, " ", ip.SrcIP)
			}

		} else if params.syn_ack_received == 1 && dns_traceroute_port == source_port {
			// we received an icmp packet and have already seen a syn ack and the sourcePort is equal to the dns traceroute port
			// put data into second list
			// to meet the TCP flow the TCP SrcPort remains unchanged when sending our DNS requesrt after receiving a Syn/Ack from a server
			// that means we cannot use the sourcePort extracted from the TCP header within the ICMP payload
			// to overcome this issue we use a custom IP.Id value when sending the DNS request
			// we set its value to 65000 + ttl (same as for tcp.SrcPort) and use it here as the hop value

			if params.initial_ip.Equal(ip.SrcIP) {
				println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t DNSTR Hop ", inner_ip.Id-uint16(start_port), " ", ip.SrcIP, "\033[0m")
			} else {
				println(3, id_from_port(uint16(start_port)), "[*] \t DNSTR Hop ", inner_ip.Id-uint16(start_port), " ", ip.SrcIP)
			}
		}
	} else {
		tcp_layer := pkt.Layer(layers.LayerTypeTCP)
		if tcp_layer == nil {
			return
		}
		tcp, ok := tcp_layer.(*layers.TCP)
		if !ok { // skip wrong packets
			return
		}
		tcpflags := TCP_flags{
			PSH: tcp.PSH,
			FIN: tcp.FIN,
			SYN: tcp.SYN,
			RST: tcp.RST,
			ACK: tcp.ACK,
		}

		start_port := calc_start_port(uint16(tcp.DstPort))
		params, exists := tracert_params[start_port]
		if !exists {
			// dont know where this packet came from but its not part of the scan
			return
		}

		if pkt.ApplicationLayer() == nil {
			if tcpflags.is_SYN() {
				// recevied a SYN packet whysoever!?
				// we make sure to put it in our data queue
				// check if item in map and assign value
				println(4, id_from_port(uint16(start_port)), "[*] Received unexpected SYN from ", ip.SrcIP)
			} else
			// SYN-ACK
			if tcpflags.is_SYN_ACK() {
				println(5, id_from_port(uint16(start_port)), "received SYN-ACK")
				if params.syn_ack_received == -1 {
					// first syn ack -> put into icmp queue
					// we start dns traceroute only for the first packet!
					// stop processing icmp packets with source port <= 65100
					// check if item in map and assign value
					dns_icmp_data.mu.Lock()
					root_data_item, ok := dns_icmp_data.items[scan_item_key{tcp.DstPort}]
					dns_icmp_data.mu.Unlock()
					if !ok {
						// if not this can be an syn/ack from previous scan
						// we ignore it
						//log.Println("ignoring packet")
						return
					}
					intValue := int(tcp.DstPort)
					hop := intValue - start_port
					if params.initial_ip.Equal(ip.SrcIP) {
						println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t Hop ", hop, " ", ip.SrcIP, "\033[0m")
					} else {
						println(3, id_from_port(uint16(start_port)), "[*] \t Hop ", hop, " ", ip.SrcIP)
					}
					println(4, id_from_port(uint16(start_port)), "[*] Received SYN/ACK from ", ip.SrcIP)
					params.traceroute_mutex.Lock()
					params.syn_ack_received = time.Now().Unix()
					params.first_to_syn_ack = ip.SrcIP
					// memorize the port we use for dns traceroute as it needs to stay constant to match the state
					dns_traceroute_port = tcp.DstPort
					params.traceroute_mutex.Unlock()
					println(4, id_from_port(uint16(start_port)), "[*] Initializing DNS Traceroute to ", ip.SrcIP, " over ", root_data_item.ip)
					last_data_item := root_data_item.last()
					// this should not occur, this would be the case if a syn-ack is being received more than once
					if last_data_item != root_data_item {
						//log.Println("error2")
						return
					}
					data := scan_data_item{
						id:   last_data_item.id,
						ts:   time.Now(),
						port: tcp.DstPort,
						seq:  tcp.Seq,
						ack:  tcp.Ack,
						ip:   ip.SrcIP,
						flags: TCP_flags{
							FIN: tcp.FIN,
							SYN: tcp.SYN,
							RST: tcp.RST,
							PSH: tcp.PSH,
							ACK: tcp.ACK,
						},
					}
					last_data_item.Next = &data

					limiter := rate.NewLimiter(rate.Every(5*time.Millisecond), 1)
					for i := 1; i < 30; i++ {
						r := limiter.Reserve()
						if !r.OK() {
							println(1, id_from_port(uint16(start_port)), "[Sending PA with DNS] Rate limit exceeded")
						}
						time.Sleep(r.Delay())
						send_ack_with_dns(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, uint8(i))
					}
					params.traceroute_mutex.Lock()
					params.all_dns_packets_sent = true
					params.traceroute_mutex.Unlock()

				} else {
					if !(params.initial_ip.Equal(ip.SrcIP)) && !(params.first_to_syn_ack.Equal(ip.SrcIP)) {
						// received SA from IP that is different to initialIP and the IP addr. that sent first SA
						//intValue := int(tcp.DstPort)
						//hop := intValue - 65000
						// we need to comment this out, otherwise we might see SynAcks from previous measurements
						//log.Println("[*] Hop ", hop, " ", ip.SrcIP)
						//log.Println("[*] Received another SYN/ACK from ", ip.SrcIP)
						return
					}

				}

			} else
			// FIN-ACK
			if tcpflags.is_FIN_ACK() {
				println(5, id_from_port(uint16(start_port)), "received FIN-ACK")
				dns_icmp_data.mu.Lock()
				root_data_item, ok := dns_icmp_data.items[scan_item_key{tcp.DstPort}]
				dns_icmp_data.mu.Unlock()
				if !ok {
					return
				}

				last_data_item := root_data_item.last()
				if !(last_data_item.flags.is_PSH_ACK()) {
					println(4, id_from_port(uint16(start_port)), "missing PSH-ACK, dropping")
					// to do this properly in theory, we would also need to send a FIN-ACK back to the server here,
					// because the connection we once established still remains intact and the remote server is asking to terminate it
					send_ack_pos_fin(ip.SrcIP, tcp.DstPort, tcp.Seq, tcp.Ack, true)
					// TODO now we could check if the correct key ACK-(1+DNS_PAYLOAD_SIZE) exists and remove that one from the dictionary
					return
				}
				println(5, id_from_port(uint16(start_port)), "ACKing FIN-ACK")
				send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
				params.active.Unlock()
			}
		} else
		// PSH-ACK || FIN-PSH-ACK == DNS Response
		if tcpflags.is_PSH_ACK() || tcpflags.is_FIN_PSH_ACK() {
			// TODO there is the case where some dns servers tend to respond to the initial query
			// only after a very long time (more than 120 seconds)
			// meanwhile they send keep-alive packets (with what seems like exponentially increasing delay)
			// I'm not yet sure if we should handle this case
			// this would mean updating the timeout to not trigger the keys removal from the map
			// if we dont handle this case though, maybe we should sent out FIN-ACKs which we would have to respond to with an ACK
			// which is a bit difficult as we dont really know if the receiving FIN-ACKs are in response to ours or self-initiated (or just RSTs)
			// if we dont terminate the connection it might interfere with another newly established connection

			println(5, id_from_port(uint16(start_port)), "received PSH-ACK or FIN-PSH-ACK")
			// decode as DNS Packet
			dns := &layers.DNS{}
			// remove the first two bytes of the payload, i.e. size of the dns response
			// see build_ack_with_dns()
			if len(tcp.LayerPayload()) <= 2 {
				//TODO this could be the point where we handle the keep-alive pkt
				println(4, id_from_port(uint16(start_port)), "[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from ", ip.SrcIP)
				return
			}
			// validate payload size
			pld_size := int(tcp.LayerPayload()[0]) + int(tcp.LayerPayload()[1])<<8
			if pld_size == len(tcp.LayerPayload())-2 {
				return
			}
			pld := make([]byte, len(tcp.LayerPayload())-2)
			for i := 0; i < len(pld); i++ {
				pld[i] = tcp.LayerPayload()[i+2]
			}
			err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
			if err != nil {
				println(3, id_from_port(uint16(start_port)), "[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from", ip.SrcIP)
				return
			}
			println(5, id_from_port(uint16(start_port)), "got DNS response")
			// we can neither use the tcp.DstPort nor the IP.Id field when receiving a valid DNS response
			// therefore we use the dns.ID field which we set in the same manner as the IP.Id and tcp.SrcPort/DstPort field
			// 65000 + ttl
			if params.initial_ip.Equal(ip.SrcIP) {
				println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t DNSTR Hop ", dns.ID-uint16(start_port), " ", ip.SrcIP, "\033[0m")
			} else {
				println(3, id_from_port(uint16(start_port)), "[*] \t DNSTR Hop ", dns.ID-uint16(start_port), " ", ip.SrcIP)
			}
			params.traceroute_mutex.Lock()
			dns_traceroute_hop_counter += 1
			params.traceroute_mutex.Unlock()
			println(3, id_from_port(uint16(start_port)), "[*] Received DNS response from ", ip.SrcIP)
			// check if item in map and assign value
			dns_icmp_data.mu.Lock()
			root_data_item, ok := dns_icmp_data.items[scan_item_key{tcp.DstPort}]
			dns_icmp_data.mu.Unlock()
			if !ok {
				return
			}
			last_data_item := root_data_item.last()
			// this should not occur, this would be the case if a psh-ack is being received more than once
			if last_data_item.flags.is_PSH_ACK() {
				println(5, id_from_port(uint16(start_port)), "already received PSH-ACK")
				return
			}
			if !(last_data_item.flags.is_SYN_ACK()) {
				println(5, id_from_port(uint16(start_port)), "missing SYN-ACK")
				return
			}
			answers := dns.Answers
			var answers_ip []net.IP
			for _, answer := range answers {
				if answer.IP != nil {
					answers_ip = append(answers_ip, answer.IP)
					println(3, id_from_port(uint16(start_port)), "[*] \t DNS answer: ", answer.IP)
				} else {
					println(5, id_from_port(uint16(start_port)), "non IP type found in answer")
					return
				}
			}
			data := scan_data_item{
				id:   last_data_item.id,
				ts:   time.Now(),
				port: tcp.DstPort,
				seq:  tcp.Seq,
				ack:  tcp.Ack,
				ip:   ip.SrcIP,
				flags: TCP_flags{
					FIN: tcp.FIN,
					SYN: tcp.SYN,
					RST: tcp.RST,
					PSH: tcp.PSH,
					ACK: tcp.ACK,
				},
				dns_recs: answers_ip,
			}
			last_data_item.Next = &data
			params.traceroute_mutex.Lock()
			params.dns_reply_received = time.Now().Unix()
			params.traceroute_mutex.Unlock()
			// send FIN-ACK to server
			send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
		}
	}
}

func packet_capture(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	println(3, "", "starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go handle_pkt(pkt)
		case <-stop_chan:
			println(3, "", "stopping packet capture")
			return
		}
	}
}

/*
start_port must be a multiple of 32
*/
func send_syn(id uint32, dst_ip net.IP, ttl uint8, start_port uint16) {
	// generate sequence number based on the first 21 bits of the hash
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort(start_port + uint16(ttl))
	println(5, id_from_port(start_port), dst_ip, "seq_num=", seq)

	dns_icmp_data.mu.Lock()
	s_d_item := scan_data_item{
		id:   id,
		ts:   time.Now(),
		ip:   dst_ip,
		port: port,
		seq:  seq,
		ack:  0,
		flags: TCP_flags{
			FIN: false,
			ACK: false,
			RST: false,
			PSH: false,
			SYN: true,
		},
		dns_recs: nil,
		Next:     nil,
	}
	dns_icmp_data.items[scan_item_key{port}] = &s_d_item
	dns_icmp_data.mu.Unlock()

	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      ttl,
		SrcIP:    net.ParseIP(cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       start_port + uint16(ttl),
	}
	//log.Println(ip.Id)
	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: port,
		DstPort: 53,
		SYN:     true,
		Seq:     seq,
		Ack:     0,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	send_tcp_pkt(ip, tcp, nil)
}

func calc_start_port(port uint16) int {
	return (int)(port - port%32)
}

func id_from_port(port uint16) int {
	return (int)(port-lowest_port) / 32
}

func init_traceroute(start_port uint16) {
	defer wg.Done()
	for {
		select {
		case netip := <-ip_chan:
			println(3, id_from_port(start_port), "[*] TCP Traceroute to ", netip)
			params, exists := tracert_params[(int)(start_port)]
			if !exists {
				params = &tracert_param{}
				tracert_params[(int)(start_port)] = params
			}
			params.active.Lock()
			params.zero()
			params.initial_ip = netip
			for i := 1; i <= 30; i++ {
				r := send_limiter.Reserve()
				if !r.OK() {
					println(1, id_from_port(start_port), "[Initial SYN] Rate limit exceeded")
				}
				time.Sleep(r.Delay())
				send_syn(uint32(i), netip, uint8(i), start_port)
			}
			params.traceroute_mutex.Lock()
			params.all_syns_sent = true
			params.traceroute_mutex.Unlock()
		case <-stop_chan:
			return
		}
	}

}

// stop measurement if we've sent out all syn packets but still got no syn ack after 3 seconds
// 1 second should be sufficient in theory, but as we may route to targets that are geographically far away we do not want to miss their responses
// we also stop if we got a SYN ACK packet but no DNS response after three seconds of sending the last DNS packet
func timeout() {
	defer wg.Done()
	for {
		select {
		case <-time.After(1 * time.Second):
			for start_port, tracert := range tracert_params {
				if tracert.all_syns_sent {
					if !tracert.all_dns_packets_sent {
						if tracert.syn_ack_received != -1 && time.Now().Unix()-tracert.syn_ack_received > 3 {
							println(3, id_from_port(uint16(start_port)), "[*] No target reached.")
							tracert.active.Unlock()
						}
					} else {
						if tracert.dns_reply_received != -1 && time.Now().Unix()-tracert.dns_reply_received > 3 {
							println(3, id_from_port(uint16(start_port)), "[*] No DNS reply received.")
							tracert.active.Unlock()
						}
					}
				}
			}
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
		select {
		case <-stop_chan:
			return
		default:
			line := scanner.Text()
			if line == "" {
				continue
			}
			ip_chan <- net.ParseIP(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	println(3, "READ-IPS", "read all ips, waiting to end ...")
	waiting_to_end = true
	time.Sleep(10 * time.Second)
	close(stop_chan)
}

func close_handle(handle *pcapgo.EthernetHandle) {
	defer wg.Done()
	<-stop_chan
	println(3, "", "closing handle")
	handle.Close()
	println(3, "", "handle closed")
}

func load_config() {
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		panic(err)
	}
	println(6, "", "config:", cfg)
}

func main() {
	// TODO run iptables command so that kernel doesnt send out RSTs
	// sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

	// command line args
	if len(os.Args) < 1 {
		println(0, "", "ERR need IPv4 target address or filename")
		return
	}
	var netip net.IP = net.ParseIP(os.Args[1])
	if netip != nil {
		println(3, "", "single ip mode")
		ip_chan <- netip
	} else {
		println(3, "", "filename mode")
		filename := os.Args[1]
		wg.Add(1)
		go read_ips_file(filename)
	}

	// handle ctrl+c SIGINT
	go func() {
		interrupt_chan := make(chan os.Signal, 1)
		signal.Notify(interrupt_chan, os.Interrupt)
		<-interrupt_chan
		if waiting_to_end {
			println(3, "", "already ending")
		} else {
			println(3, "", "received SIGINT, ending")
			close(stop_chan)
		}
	}()

	load_config()
	send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/cfg.Pkts_per_sec)*time.Microsecond), 1)
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0, 0)
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
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, fmt.Sprint("(icmp or (tcp and src port 53)) and ip dst ", cfg.Iface_ip)) //, " and src port 53"))
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err = net.ListenPacket("ip4:tcp", cfg.Iface_ip)
	if err != nil {
		panic(err)
	}
	raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}

	// start packet capture as goroutine
	wg.Add(3)
	go packet_capture(handle)
	time.Sleep(100 * time.Millisecond)
	go timeout()
	var i uint16 = 0
	for ; i < 1; i++ {
		wg.Add(1)
		go init_traceroute(uint16(lowest_port) + 32*i)
	}
	go close_handle(handle)
	wg.Wait()
	println(3, "", "all routines finished")
	println(3, "", "program done")
}
