package main

import (
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

const (
	debug = false
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
}

var cfg cfg_db

var wg sync.WaitGroup
var raw_con *ipv4.RawConn

type stop struct{}

var stop_chan = make(chan stop) // (〃・ω・〃)
var ip_chan = make(chan net.IP, 1024)

var blocked_nets []*net.IPNet = []*net.IPNet{}

// a simple struct for all the tcp flags needed
type TCP_flags struct {
	FIN, SYN, RST, PSH, ACK bool
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

var initialIP net.IP
var firstToSynAck net.IP

var dns_traceroute_hop_counter = 0

var waiting_to_end = false

var traceroute_mutex sync.Mutex
var all_syns_sent = false
var all_dns_packets_sent = false
var syn_ack_received = false
var dns_reply_received = false

var dns_traceroute_port = layers.TCPPort(10000)

/*	id:
*	(seq-num)		(Ports from 61440)   	(2048 byte padding)
*	2^32	*			2^11			/			 2^11		=2^32
*
*	increment: |y=11*x | z=21*x|
*	seq_num = z*2^11, max:2^32-2^11
*	port = y+15<<15 = y+61440
 */

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
		Id:       65000+uint16(ttl),
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
		ID:        uint16(65000 + uint32(ttl)),
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
	var sourcePort layers.TCPPort
	var inner_ip *layers.IPv4

	ip_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ip_layer == nil {
		return
	}
	ip, ok := ip_layer.(*layers.IPv4)
	if !ok {
		return
	}
	icmp_layer := pkt.Layer(layers.LayerTypeICMPv4)
	icmp, ok := icmp_layer.(*layers.ICMPv4)
	if icmp != nil {
		if debug {
			log.Println("received ICMP packet")
		}
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

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			inner_ip, _ = ipLayer.(*layers.IPv4)
			// Decode source port (first 2 bytes)
			sourcePort = layers.TCPPort(binary.BigEndian.Uint16(inner_ip.Payload[:2]))
			//log.Println("Source port: ",sourcePort)
			//log.Println("Destination Port:", tcp.DstPort)
			// Add more fields as needed
		} else {
			// no tcp layer means not of interest to us!
			//log.Println("No TCP layer found in the payload.")
			return
		}
		// if we did not receive a syn ack and the source port is <= 65100 (which we use for all the syns we sent) add this to the
		if !syn_ack_received && sourcePort >= 65000 && sourcePort < 65100 {
			intValue := int(sourcePort)
			hop := intValue - 65000
			if initialIP.Equal(ip.SrcIP){
				log.Println("\033[0;31m[*] \t Hop ", hop, " ", ip.SrcIP,"\033[0m")
			}else{
				log.Println("[*] \t Hop ", hop, " ", ip.SrcIP)
			}

		} else if syn_ack_received && dns_traceroute_port == sourcePort {
			// we received an icmp packet and have already seen a syn ack and the sourcePort is equal to the dns traceroute port
			// put data into second list
			// to meet the TCP flow the TCP SrcPort remains unchanged when sending our DNS requesrt after receiving a Syn/Ack from a server 
			// that means we cannot use the sourcePort extracted from the TCP header within the ICMP payload
			// to overcome this issue we use a custom IP.Id value when sending the DNS request
			// we set its value to 65000 + ttl (same as for tcp.SrcPort) and use it here as the hop value
			
			if initialIP.Equal(ip.SrcIP){
				log.Println("\033[0;31m[*] \t DNSTR Hop ", inner_ip.Id-65000, " ", ip.SrcIP,"\033[0m")
			}else{
				log.Println("[*] \t DNSTR Hop ", inner_ip.Id-65000, " ", ip.SrcIP)
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
		if pkt.ApplicationLayer() == nil {
			if tcpflags.is_SYN() {
				// recevied a SYN packet whysoever!?
				// we make sure to put it in our data queue
				// check if item in map and assign value
				log.Println("[*] Received unexpected SYN from ", ip.SrcIP)
			} else
			// SYN-ACK
			if tcpflags.is_SYN_ACK() {
				if debug {
					log.Println("received SYN-ACK")
				}
				if !syn_ack_received {
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
					hop := intValue - 65000
					if initialIP.Equal(ip.SrcIP){
						log.Println("\033[0;31m[*] \t Hop ", hop, " ", ip.SrcIP,"\033[0m")
					}else{
						log.Println("[*] \t Hop ", hop, " ", ip.SrcIP)
					}
					log.Println("[*] Received SYN/ACK from ", ip.SrcIP)
					traceroute_mutex.Lock()
					syn_ack_received = true
					firstToSynAck = ip.SrcIP
					// memorize the port we use for dns traceroute as it needs to stay constant to match the state
					dns_traceroute_port = tcp.DstPort
					traceroute_mutex.Unlock()
					log.Println("[*] Initializing DNS Traceroute to ", ip.SrcIP, " over ", root_data_item.ip)
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
						//wg.Add(1)
						r := limiter.Reserve()
						if !r.OK() {
							log.Println("[Sending PA with DNS] Rate limit exceeded")
							break
						}
						time.Sleep(r.Delay())
						send_ack_with_dns(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, uint8(i))
					}
					traceroute_mutex.Lock()
					all_dns_packets_sent = true
					traceroute_mutex.Unlock()

				} else {
					if !(initialIP.Equal(ip.SrcIP)) && !(firstToSynAck.Equal(ip.SrcIP)) {
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
				if debug {
					log.Println("received FIN-ACK")
				}
				dns_icmp_data.mu.Lock()
				root_data_item, ok := dns_icmp_data.items[scan_item_key{tcp.DstPort}]
				dns_icmp_data.mu.Unlock()
				if !ok {
					return
				}

				last_data_item := root_data_item.last()
				if !(last_data_item.flags.is_PSH_ACK()) {
					if debug {
						log.Println("missing PSH-ACK, dropping")
					}
					// to do this properly in theory, we would also need to send a FIN-ACK back to the server here,
					// because the connection we once established still remains intact and the remote server is asking to terminate it
					send_ack_pos_fin(ip.SrcIP, tcp.DstPort, tcp.Seq, tcp.Ack, true)
					// TODO now we could check if the correct key ACK-(1+DNS_PAYLOAD_SIZE) exists and remove that one from the dictionary
					return
				}
				if debug {
					log.Println("ACKing FIN-ACK")
				}
				send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
				waiting_to_end = true
				time.Sleep(3 * time.Second)
				close(stop_chan)
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

			if debug {
				log.Println("received PSH-ACK or FIN-PSH-ACK")
			}
			// decode as DNS Packet
			dns := &layers.DNS{}
			// remove the first two bytes of the payload, i.e. size of the dns response
			// see build_ack_with_dns()
			if len(tcp.LayerPayload()) <= 2 {
				//TODO this could be the point where we handle the keep-alive pkt
				log.Println("[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from ",ip.SrcIP)
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
				if debug {
					log.Println("DNS not found")
				}
				log.Println("[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from", ip.SrcIP)
				return
			}
			if debug {
				log.Println("got DNS response")
			}
			// we can neither use the tcp.DstPort nor the IP.Id field when receiving a valid DNS response
			// therefore we use the dns.ID field which we set in the same manner as the IP.Id and tcp.SrcPort/DstPort field
			// 65000 + ttl
			if initialIP.Equal(ip.SrcIP){
				log.Println("\033[0;31m[*] \t DNSTR Hop ", dns.ID-65000, " ", ip.SrcIP,"\033[0m")
			}else{
				log.Println("[*] \t DNSTR Hop ", dns.ID-65000, " ", ip.SrcIP)
			}
			traceroute_mutex.Lock()
			dns_traceroute_hop_counter += 1
			traceroute_mutex.Unlock()
			log.Println("[*] Received DNS response from ", ip.SrcIP)
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
				if debug {
					log.Println("already received PSH-ACK")
				}
				return
			}
			if !(last_data_item.flags.is_SYN_ACK()) {
				if debug {
					log.Println("missing SYN-ACK")
				}
				return
			}
			answers := dns.Answers
			var answers_ip []net.IP
			for _, answer := range answers {
				if answer.IP != nil {
					answers_ip = append(answers_ip, answer.IP)
					log.Println("[*] \t DNS answer: ", answer.IP)
				} else {
					if debug {
						log.Println("non IP type found in answer")
					}
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
			traceroute_mutex.Lock()
			dns_reply_received = true
			traceroute_mutex.Unlock()
			// send FIN-ACK to server
			send_ack_pos_fin(root_data_item.ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
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
			go handle_pkt(pkt)
		case <-stop_chan:
			if debug {
				log.Println("stopping packet capture")
			}
			return
		}
	}
}

func send_syn(id uint32, dst_ip net.IP, ttl uint8) {
	// generate sequence number based on the first 21 bits of the hash
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort(65000 + uint32(ttl))
	if debug {
		log.Println(dst_ip, "seq_num=", seq)
	}

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
		Id:       65000+uint16(ttl),
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

// stop measurement if we've sent out all syn packets but still got no syn ack after 3 seconds
// 1 second should be sufficient in theory, but as we may route to targets that are geographically far away we do not want to miss their responses
// we also stop if we got a SYN ACK packet but no DNS response after three seconds of sending the last DNS packet
func timeout() {
	defer wg.Done()
	for {
		if all_syns_sent{
			if !all_dns_packets_sent{
				select {
					case <-time.After(3 * time.Second):
						if !syn_ack_received{
							log.Println("[*] No target reached.")
							close(stop_chan)
						}
					case <-stop_chan:
						return
				}
			} else{
				select {
					case <-time.After(3 * time.Second):
						if !dns_reply_received{
							log.Println("[*] No DNS reply received.")
							close(stop_chan)
						}
					case <-stop_chan:
						return
				}
			}
		}
	}
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

func ip42uint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint322ip(ipint uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipint)
	return ip
}

func main() {
	// TODO run iptables command so that kernel doesnt send out RSTs
	// sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

	// command line args
	if len(os.Args) < 1 {
		if debug {
			log.Println("ERR need IPv4 target address")
		}
		return
	}
	var netip net.IP
	netip = net.ParseIP(os.Args[1])

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
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0, 0)
	DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	// start packet capture
	handle, err := pcapgo.NewEthernetHandle(cfg.Iface_name) //pcap.OpenLive("wlp1s0", defaultSnapLen, true,
	//pcap.BlockForever)
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
	go timeout()
	limiter := rate.NewLimiter(rate.Every(50*time.Millisecond), 1)
	initialIP = netip
	log.Println("[*] TCP Traceroute to ", netip)
	for i := 1; i <= 30; i++ {
		//wg.Add(1)
		r := limiter.Reserve()
		if !r.OK() {
			log.Println("[Initial SYN] Rate limit exceeded")
			break
		}
		time.Sleep(r.Delay())
		send_syn(uint32(i), netip, uint8(i))
	}
	traceroute_mutex.Lock()
	all_syns_sent = true
	traceroute_mutex.Unlock()

	go close_handle(handle)
	wg.Wait()
	if debug {
		log.Println("all routines finished")
	}
	if debug {
		log.Println("program done")
	}
}
