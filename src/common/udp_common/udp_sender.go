package udp_common

import (
	"dns_tools/common"
	"dns_tools/config"
	"dns_tools/logging"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type Udp_sender struct {
	L2_sender  *common.RawL2
	L3_Raw_con *ipv4.RawConn
}

func (sender *Udp_sender) Sender_init() {
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err := net.ListenPacket("ip4:udp", config.Cfg.Iface_ip)
	if err != nil {
		panic(err)
	}
	sender.L3_Raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}
}

func (sender *Udp_sender) Send_udp_pkt(ip layers.IPv4, udp layers.UDP, payload []byte) {
	if config.Cfg.Craft_ethernet {
		logging.Println(6, nil, "Layer 2 send")
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, common.Opts,
			&ip,
			&udp,
			gopacket.Payload(payload),
		); err != nil {
			panic(err)
		}

		sender.L2_sender.Send(buffer.Bytes())
	} else {
		logging.Println(6, nil, "Layer 3 send")
		ip_head_buf := gopacket.NewSerializeBuffer()
		err := ip.SerializeTo(ip_head_buf, common.Opts)
		if err != nil {
			panic(err)
		}
		ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
		if err != nil {
			panic(err)
		}

		udp_buf := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(udp_buf, common.Opts, &udp, gopacket.Payload(payload))
		if err != nil {
			panic(err)
		}

		if err = sender.L3_Raw_con.WriteTo(ip_head, udp_buf.Bytes(), nil); err != nil {
			panic(err)
		}
	}
}

func (sender *Udp_sender) Build_dns(dst_ip net.IP, src_port layers.UDPPort, dnsid uint16, query string) (layers.IPv4, layers.UDP, []byte) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolUDP,
		Id:       1,
	}

	// Create udp layer
	udp := layers.UDP{
		SrcPort: src_port,
		DstPort: layers.UDPPort(config.Cfg.Dst_port),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	// create dns layers
	qst := layers.DNSQuestion{
		Name:  []byte(query),
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
