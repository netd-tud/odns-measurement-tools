package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
	Iface_name         string `yaml:"iface_name"`
	Iface_ip           string `yaml:"iface_ip"`
	Dst_port           uint16 `yaml:"dst_port"`
	Port_min           uint16 `yaml:"port_min"`
	Port_max           uint16 `yaml:"port_max"`
	Dns_query          string `yaml:"dns_query"`
	Excl_ips_fname     string `yaml:"exclude_ips_fname"`
	Pkts_per_sec       int    `yaml:"pkts_per_sec"`
	Verbosity          int    `yaml:"verbosity"`
	Port_reuse_timeout int    `yaml:"port_reuse_timeout"`
}

var cfg cfg_db

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

var DNS_PAYLOAD_SIZE uint16

var waiting_to_end = false

var lowest_port uint16 = 61024 // smallest multiple of 32 outside random port range
var highest_port uint16

var write_chan = make(chan *tracert_param, 256)

// a simple struct for all the tcp flags needed
type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
}

// 0: OFF, 1: ERR, 2: WARN, 3: INFO, 4: DEBUG, 5: VERBOSE, 6: ALL
func println(lvl int, prefix interface{}, v ...any) {
	if lvl <= cfg.Verbosity {
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
		if prefix != nil && prefix != "" {
			u = append(u, "["+fmt.Sprintf("%v", prefix)+"]")
		}
		u = append(u, v...)
		v = u
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

type tracert_hop struct {
	hop_count   int
	ts          time.Time
	response_ip net.IP
}

type tracert_param struct {
	traceroute_mutex     sync.Mutex
	all_syns_sent        bool
	all_dns_packets_sent bool
	syn_ack_received     int64
	dns_reply_received   int64
	initial_ip           net.IP
	first_to_syn_ack     net.IP
	dns_traceroute_port  layers.TCPPort
	finished             int64
	written              bool
	syntr_hops           []tracert_hop
	dnstr_hops           []tracert_hop
	dns_answers          []net.IP
}

func (params *tracert_param) zero() {
	params.all_dns_packets_sent = false
	params.all_syns_sent = false
	params.syn_ack_received = -1
	params.dns_reply_received = -1
	params.finished = -1
	params.dns_traceroute_port = layers.TCPPort(0)
	params.written = false
	params.syntr_hops = []tracert_hop{}
	params.dnstr_hops = []tracert_hop{}
	params.dns_answers = []net.IP{}
}

var tracert_params = map[int]*tracert_param{}

var send_limiter *rate.Limiter

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
		if params.syn_ack_received == -1 && source_port >= layers.TCPPort(lowest_port) && source_port < layers.TCPPort(highest_port) {
			src_port_int := int(source_port)
			hop := src_port_int - start_port
			if params.initial_ip.Equal(ip.SrcIP) {
				println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t Hop ", hop, " ", ip.SrcIP, "\033[0m")
			} else {
				println(3, id_from_port(uint16(start_port)), "[*] \t Hop ", hop, " ", ip.SrcIP)
			}
			params.syntr_hops = append(params.syntr_hops, tracert_hop{
				hop_count:   hop,
				ts:          time.Now().UTC(),
				response_ip: ip.SrcIP,
			})

		} else if params.syn_ack_received != -1 && params.dns_traceroute_port == source_port {
			// we received an icmp packet and have already seen a syn ack and the sourcePort is equal to the dns traceroute port
			// put data into second list
			// to meet the TCP flow the TCP SrcPort remains unchanged when sending our DNS requesrt after receiving a Syn/Ack from a server
			// that means we cannot use the sourcePort extracted from the TCP header within the ICMP payload
			// to overcome this issue we use a custom IP.Id value when sending the DNS request
			// we set its value to 65000 + ttl (same as for tcp.SrcPort) and use it here as the hop value

			hop := inner_ip.Id - uint16(start_port)
			if params.initial_ip.Equal(ip.SrcIP) {
				println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t DNSTR Hop ", hop, " ", ip.SrcIP, "\033[0m")
			} else {
				println(3, id_from_port(uint16(start_port)), "[*] \t DNSTR Hop ", hop, " ", ip.SrcIP)
			}
			params.dnstr_hops = append(params.syntr_hops, tracert_hop{
				hop_count:   int(hop),
				ts:          time.Now().UTC(),
				response_ip: ip.SrcIP,
			})
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
				// received a SYN packet whysoever!?
				// we make sure to put it in our data queue
				// check if item in map and assign value
				println(3, id_from_port(uint16(start_port)), "[*] Received unexpected SYN from ", ip.SrcIP)
			} else
			// SYN-ACK
			if tcpflags.is_SYN_ACK() {
				println(5, id_from_port(uint16(start_port)), "received SYN-ACK from", ip.SrcIP, "to port", tcp.DstPort)
				if params.syn_ack_received == -1 {
					// first syn ack -> put into icmp queue
					// we start dns traceroute only for the first packet!
					hop := int(tcp.DstPort) - start_port
					if params.initial_ip.Equal(ip.SrcIP) {
						println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t Hop ", hop, " ", ip.SrcIP, "\033[0m")
					} else {
						println(3, id_from_port(uint16(start_port)), "[*] \t Hop ", hop, " ", ip.SrcIP)
					}
					println(3, id_from_port(uint16(start_port)), "[*] Received SYN/ACK from ", ip.SrcIP)
					params.traceroute_mutex.Lock()
					params.syn_ack_received = time.Now().Unix()
					params.first_to_syn_ack = ip.SrcIP
					// memorize the port we use for dns traceroute as it needs to stay constant to match the state
					if (uint16)(params.dns_traceroute_port) != 0 {
						println(3, nil, "[***] DNS Traceroute is already ongoing")
						params.traceroute_mutex.Unlock()
						return
					}
					params.dns_traceroute_port = tcp.DstPort
					params.traceroute_mutex.Unlock()
					println(3, id_from_port(uint16(start_port)), "[*] Initializing DNS Traceroute to ", ip.SrcIP, " over ", params.initial_ip)

					for i := 1; i < 30; i++ {
						r := send_limiter.Reserve()
						if !r.OK() {
							println(1, id_from_port(uint16(start_port)), "[Sending PA with DNS] Rate limit exceeded")
						}
						time.Sleep(r.Delay())
						if params.dns_reply_received != -1 {
							break
						}
						send_ack_with_dns(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, uint8(i))
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
					println(5, id_from_port(uint16(start_port)), "responding with reset to", params.initial_ip, "and port", tcp.DstPort)
					//send_rst(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack)
					send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
					send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				}
			} else
			// FIN-ACK
			if tcpflags.is_FIN_ACK() {
				println(5, id_from_port(uint16(start_port)), "received FIN-ACK from", ip.SrcIP, "to port", tcp.DstPort)
				/*if tcp.DstPort != params.dns_traceroute_port {
					return
				}*/
				println(5, id_from_port(uint16(start_port)), "ACKing FIN-ACK")
				send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
				params.traceroute_mutex.Lock()
				params.finished = time.Now().Unix()
				write_chan <- params
				params.traceroute_mutex.Unlock()
			}
		} else
		// PSH-ACK || FIN-PSH-ACK == DNS Response
		if tcpflags.is_PSH_ACK() || tcpflags.is_FIN_PSH_ACK() {
			println(5, id_from_port(uint16(start_port)), "received PSH-ACK or FIN-PSH-ACK")
			// decode as DNS Packet
			dns := &layers.DNS{}
			// remove the first two bytes of the payload, i.e. size of the dns response
			// see build_ack_with_dns()
			if len(tcp.LayerPayload()) <= 2 {
				println(3, id_from_port(uint16(start_port)), "[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from ", ip.SrcIP)
				send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			// validate payload size
			pld_size := int(tcp.LayerPayload()[0]) + int(tcp.LayerPayload()[1])<<8
			if pld_size == len(tcp.LayerPayload())-2 {
				send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			pld := make([]byte, len(tcp.LayerPayload())-2)
			for i := 0; i < len(pld); i++ {
				pld[i] = tcp.LayerPayload()[i+2]
			}
			err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
			if err != nil {
				println(3, id_from_port(uint16(start_port)), "[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from", ip.SrcIP)
				send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			println(5, id_from_port(uint16(start_port)), "got DNS response")
			// we can neither use the tcp.DstPort nor the IP.Id field when receiving a valid DNS response
			// therefore we use the dns.ID field which we set in the same manner as the IP.Id and tcp.SrcPort/DstPort field
			if params.initial_ip.Equal(ip.SrcIP) {
				println(3, id_from_port(uint16(start_port)), "\033[0;31m[*] \t DNSTR Hop ", dns.ID-uint16(start_port), " ", ip.SrcIP, "\033[0m")
			} else {
				println(3, id_from_port(uint16(start_port)), "[*] \t DNSTR Hop ", dns.ID-uint16(start_port), " ", ip.SrcIP)
			}
			println(3, id_from_port(uint16(start_port)), "[*] Received DNS response from ", ip.SrcIP)
			// check for correct port
			if tcp.DstPort != params.dns_traceroute_port {
				println(5, id_from_port(uint16(start_port)), "wrong port of PSH-ACK or missing SYN-ACK")
				send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			if len(params.dns_answers) != 0 {
				println(5, id_from_port(uint16(start_port)), "already received PSH-ACK")
				send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
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
					// return
				}
			}
			params.traceroute_mutex.Lock()
			params.dns_answers = answers_ip
			params.dns_reply_received = time.Now().Unix()
			params.traceroute_mutex.Unlock()
			// send FIN-ACK to server
			send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
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
	// generate sequence number based on the first 21 bits of id
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort(start_port + uint16(ttl))
	println(5, id_from_port(start_port), "sending syn to", dst_ip, "with seq_num=", seq)

	_, ok := tracert_params[int(start_port)]
	if !ok {
		println(1, nil, "params object not present for start_port:", start_port)
		return
	}

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
			params, exists := tracert_params[(int)(start_port)]
			if !exists {
				params = &tracert_param{}
				tracert_params[(int)(start_port)] = params
			}
			for exists && params.written && (params.finished == 0 || time.Now().Unix()-params.finished < int64(cfg.Port_reuse_timeout)) {
				time.Sleep(1 * time.Second)
			}
			params.traceroute_mutex.Lock()
			params.zero()
			params.initial_ip = netip
			params.traceroute_mutex.Unlock()
			println(3, id_from_port(start_port), "[*] TCP Traceroute to ", netip)
			for i := 1; i <= 30; i++ {
				r := send_limiter.Reserve()
				if !r.OK() {
					println(1, id_from_port(start_port), "[Initial SYN] Rate limit exceeded")
				}
				time.Sleep(r.Delay())
				if params.syn_ack_received != -1 {
					break
				}
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
			for start_port, params := range tracert_params {
				if params.finished != -1 {
					continue
				}
				if params.all_syns_sent {
					if !params.all_dns_packets_sent {
						if params.syn_ack_received == -1 && time.Now().Unix()-params.syn_ack_received > 3 {
							println(3, id_from_port(uint16(start_port)), "[*] No target reached.")
							params.traceroute_mutex.Lock()
							params.finished = time.Now().Unix()
							write_chan <- params
							params.traceroute_mutex.Unlock()
						}
					} else { // all dns packets sent
						if params.dns_reply_received == -1 && time.Now().Unix()-params.dns_reply_received > 3 {
							println(3, id_from_port(uint16(start_port)), "[*] No DNS reply received.")
							params.traceroute_mutex.Lock()
							params.finished = time.Now().Unix()
							write_chan <- params
							params.traceroute_mutex.Unlock()
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

func (params *tracert_param) str_dns_answers() []string {
	dns_answers_str := ""
	for idx, answer := range params.dns_answers {
		dns_answers_str += answer.String()
		if idx < len(params.dns_answers)-1 {
			dns_answers_str += ","
		}
	}
	dns_slice := []string{"DNSANS", dns_answers_str}
	println(6, "str_dns_answers", "dns_answers:", params.dns_answers, "dns_answers_str:", dns_answers_str, "slice:", dns_slice)
	return dns_slice
}

func write_results() {
	defer wg.Done()
	data_folder := "traceroute_data"
	formatted_ts := time.Now().UTC().Format("2006-01-02_15-04-05")
	save_path := filepath.Join(data_folder, formatted_ts)
	err := os.MkdirAll(save_path, os.ModePerm)
	if err != nil {
		println(1, nil, "could not create output directory")
	}
	for {
		select {
		case params := <-write_chan:
			println(3, "writeout", "writing results for", params.initial_ip.String())
			filepath := filepath.Join(save_path, params.initial_ip.String()+".csv.gz")
			csvfile, err := os.Create(filepath)
			if err != nil {
				panic(err)
			}
			defer csvfile.Close()

			zip_writer := gzip.NewWriter(csvfile)
			defer zip_writer.Close()

			writer := csv.NewWriter(zip_writer)
			writer.Comma = ';'
			defer writer.Flush()

			// format:
			// 1st field = tag: <SYNTR|DNSTR|DNSANS>
			// SYNTR;TS;HOP;RESPIP
			// DNSTR;TS;HOP;RESPIP
			// DNSANS;ANSWERIP1,ANSWERIP2
			//writer.Write(params_to_strarr(params))
			for _, syntrhop := range params.syntr_hops {
				writer.Write([]string{"SYNTR", syntrhop.ts.Format("2006-01-02 15:04:05.000000"), strconv.Itoa(syntrhop.hop_count), syntrhop.response_ip.String()})
			}
			for _, dnstrhop := range params.dnstr_hops {
				writer.Write([]string{"DNSTR", dnstrhop.ts.Format("2006-01-02 15:04:05.000000"), strconv.Itoa(dnstrhop.hop_count), dnstrhop.response_ip.String()})
			}
			writer.Write(params.str_dns_answers())
			params.traceroute_mutex.Lock()
			params.written = true
			params.traceroute_mutex.Unlock()
		case <-stop_chan:
			return
		}
	}
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
		go func() {
			waiting_to_end = true
			time.Sleep(10 * time.Second)
			close(stop_chan)
		}()
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
	wg.Add(4)
	go packet_capture(handle)
	time.Sleep(100 * time.Millisecond)
	go timeout()
	go write_results()
	var i uint16 = 0
	var number_routines uint16 = 10
	highest_port = lowest_port + 32*number_routines
	println(3, nil, "lowest port:", lowest_port)
	println(3, nil, "highest port:", highest_port)
	for ; i < number_routines; i++ {
		wg.Add(1)
		go init_traceroute(uint16(lowest_port) + 32*i)
	}
	go close_handle(handle)
	wg.Wait()
	println(3, "", "all routines finished")
	println(3, "", "program done")
}
