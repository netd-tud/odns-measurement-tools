package udpscanner

import (
	"dns_tools/scanner"

	"github.com/gopacket/gopacket/layers"
)

func (udps *Udp_scanner) send_followup(probe *scanner.Follow_up) {
	var key udp_scan_item_key
	var item *Udp_scan_data_item
	for {
		id, _, dnsid := udps.update_sync_init()
		key = udp_scan_item_key{layers.UDPPort(probe.Source_port), dnsid}
		item = &Udp_scan_data_item{Id: id, Ts_req: probe.Sent, Ip: probe.Target_ip, Port: key.port, Dnsid: dnsid, Followup: probe}
		udps.Scan_data.Mu.Lock()
		_, used := udps.Scan_data.Items[key]
		if !used {
			udps.Scan_data.Items[key] = item
		}
		udps.Scan_data.Mu.Unlock()
		if !used {
			break
		}
	}
	if !probe.On_complete(func(string) {
		udps.Scan_data.Mu.Lock()
		if udps.Scan_data.Items[key] == item {
			delete(udps.Scan_data.Items, key)
		}
		udps.Scan_data.Mu.Unlock()
	}) {
		return
	}
	udps.send_udp(udps.Build_dns_question(probe.Target_ip, key.port, key.dnsid, probe.Query.Question(), probe.RD))
	probe.Query_sent()
}

func (udps *Udp_scanner) send_udp(ip layers.IPv4, udp layers.UDP, payload []byte) {
	if udps.send_packet != nil {
		udps.send_packet(ip, udp, payload)
		return
	}
	udps.Send_udp_pkt(ip, udp, payload)
}
