package tcpscanner

import (
	"dns_tools/config"
	"dns_tools/scanner"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// These keys cannot collide with the primary scanner's (port, sequence) keys.
type followup_connection_key struct {
	port layers.TCPPort
	seq  uint32
}
type followup_ack_key struct {
	port layers.TCPPort
	ack  uint32
}

type followup_connection struct {
	probe               *scanner.Follow_up
	ip                  layers.IPv4
	tcp                 layers.TCP
	payload             []byte
	dnsid               uint16
	expected_ack        uint32
	next_seq            uint32
	handshake, answered bool
}

func (c *followup_connection) Get_timestamp() time.Time { return c.probe.Sent }

func (tcps *Tcp_scanner) remove_followup(c *followup_connection) {
	delete(tcps.Scan_data.Items, followup_connection_key{c.tcp.SrcPort, c.tcp.Seq})
	delete(tcps.Scan_data.Items, followup_ack_key{c.tcp.SrcPort, c.expected_ack})
}

func (tcps *Tcp_scanner) send_followup(probe *scanner.Follow_up) {
	id := tcps.get_next_id()
	seq, port := (id&0x1FFFFF)*2048, layers.TCPPort((id>>21)+61440)
	dnsid := uint16(rand.Intn(65536))
	ip, tcp, payload := tcps.Build_ack_with_question(probe.Target_ip, port, 0, seq, probe.Query.Question(), dnsid, probe.RD)
	tcp.SYN, tcp.ACK, tcp.PSH, tcp.Ack = true, false, false, 0
	c := &followup_connection{probe: probe, ip: ip, tcp: tcp, payload: payload, dnsid: dnsid, expected_ack: seq + 1}
	tcps.Scan_data.Mu.Lock()
	tcps.Scan_data.Items[followup_connection_key{port, seq}] = c
	tcps.Scan_data.Items[followup_ack_key{port, c.expected_ack}] = c
	tcps.Scan_data.Mu.Unlock()
	if !probe.On_complete(func(status string) {
		// Keep FIN tracking until close or the existing scanner timeout.
		if status == "response" {
			return
		}
		tcps.Scan_data.Mu.Lock()
		tcps.remove_followup(c)
		tcps.Scan_data.Mu.Unlock()
	}) {
		return
	}
	tcps.send_tcp(ip, tcp, nil)
}

func (tcps *Tcp_scanner) send_followup_packet(c *followup_connection, seq, ack uint32, payload []byte, fin bool) {
	tcp := c.tcp
	tcp.Seq, tcp.Ack = seq, ack
	tcp.SYN, tcp.ACK, tcp.PSH, tcp.FIN = false, true, len(payload) != 0, fin
	tcps.send_tcp(c.ip, tcp, payload)
}

// Follow-up connections use their own state; the original primary handler stays intact.
func (tcps *Tcp_scanner) handle_followup_pkt(ip *layers.IPv4, tcp *layers.TCP) bool {
	if tcps.Followups == nil || tcp.SrcPort != layers.TCPPort(config.Cfg.Dst_port) || !tcp.ACK {
		return false
	}
	key := followup_ack_key{tcp.DstPort, tcp.Ack}
	tcps.Scan_data.Mu.Lock()
	item, ok := tcps.Scan_data.Items[key]
	if !ok {
		tcps.Scan_data.Mu.Unlock()
		return false
	}
	c := item.(*followup_connection)
	if tcp.RST {
		tcps.remove_followup(c)
		answered := c.answered
		tcps.Scan_data.Mu.Unlock()
		if !answered {
			c.probe.Complete("reset", nil, nil, nil)
		}
		return true
	}
	if tcp.SYN && !tcp.FIN && len(tcp.Payload) == 0 && !c.handshake {
		c.handshake, c.next_seq = true, tcp.Seq+1
		delete(tcps.Scan_data.Items, key)
		c.expected_ack = c.tcp.Seq + 1 + uint32(len(c.payload))
		tcps.Scan_data.Items[followup_ack_key{c.tcp.SrcPort, c.expected_ack}] = c
		tcps.Scan_data.Mu.Unlock()
		tcps.send_followup_packet(c, tcp.Ack, tcp.Seq+1, c.payload, false)
		return true
	}
	if c.answered {
		if tcp.FIN && len(tcp.Payload) == 0 && tcp.Seq == c.next_seq {
			tcps.remove_followup(c)
			tcps.Scan_data.Mu.Unlock()
			tcps.send_followup_packet(c, tcp.Ack, tcp.Seq+1, nil, false)
			return true
		}
		tcps.Scan_data.Mu.Unlock()
		return true
	}
	if !c.handshake || tcp.SYN || tcp.Seq != c.next_seq || len(tcp.Payload) < 2 || int(binary.BigEndian.Uint16(tcp.Payload[:2])) != len(tcp.Payload)-2 {
		tcps.Scan_data.Mu.Unlock()
		return true
	}
	dns := &layers.DNS{}
	payload := tcp.Payload[2:]
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || dns.ID != c.dnsid || !scanner.Match_question(dns, c.probe.Query.Question()) {
		tcps.Scan_data.Mu.Unlock()
		return true
	}
	c.answered, c.next_seq = true, tcp.Seq+uint32(len(tcp.Payload))
	delete(tcps.Scan_data.Items, key)
	c.expected_ack = tcp.Ack + 1
	ack := c.next_seq
	if tcp.FIN {
		ack++
		tcps.remove_followup(c)
	} else {
		tcps.Scan_data.Items[followup_ack_key{c.tcp.SrcPort, c.expected_ack}] = c
	}
	tcps.Scan_data.Mu.Unlock()
	tcps.send_followup_packet(c, tcp.Ack, ack, nil, true)
	c.probe.Complete("response", ip.SrcIP, dns, payload)
	return true
}

func (tcps *Tcp_scanner) send_tcp(ip layers.IPv4, tcp layers.TCP, payload []byte) {
	if tcps.send_packet != nil {
		tcps.send_packet(ip, tcp, payload)
		return
	}
	tcps.Send_tcp_pkt(ip, tcp, payload)
}

// Preserve the original primary ACK/FIN sender; allow packet fixtures to intercept it.
func (tcps *Tcp_scanner) send_ack_pos_fin(dst net.IP, port layers.TCPPort, seq, ack uint32, fin bool) {
	if tcps.send_packet == nil {
		tcps.Send_ack_pos_fin(dst, port, seq, ack, fin)
		return
	}
	ip, tcp, _ := tcps.Build_ack_with_dns(dst, port, seq, ack)
	tcp.PSH, tcp.FIN = false, fin
	tcps.send_packet(ip, tcp, nil)
}
