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
