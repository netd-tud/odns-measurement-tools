package tcp_common

import (
	"dns_tools/common"
	"dns_tools/config"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type Tcp_sender struct {
	L2_sender  *common.RawL2
	L3_Raw_con *ipv4.RawConn
}

func (sender *Tcp_sender) Sender_init() {
	// create raw l3 socket
	var pkt_con net.PacketConn
	pkt_con, err := net.ListenPacket("ip4:tcp", config.Cfg.Iface_ip)
	if err != nil {
		panic(err)
	}
	sender.L3_Raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}
}

func (sender *Tcp_sender) Send_tcp_pkt(ip layers.IPv4, tcp layers.TCP, payload []byte) {
	if config.Cfg.Craft_ethernet {
		tcp_buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(tcp_buf, common.Opts, &ip, &tcp, gopacket.Payload(payload))
		if err != nil {
			panic(err)
		}

		sender.L2_sender.Send(tcp_buf.Bytes())
	} else {
		ip_head_buf := gopacket.NewSerializeBuffer()
		err := ip.SerializeTo(ip_head_buf, common.Opts)
		if err != nil {
			panic(err)
		}
		ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
		if err != nil {
			panic(err)
		}
		tcp_buf := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(tcp_buf, common.Opts, &tcp, gopacket.Payload(payload))
		if err != nil {
			panic(err)
		}
		if err = sender.L3_Raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
			panic(err)
		}
	}
}

func (sender *Tcp_sender) Send_ack_pos_fin(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, fin bool) {
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
		FIN:     fin,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	sender.Send_tcp_pkt(ip, tcp, nil)
}
