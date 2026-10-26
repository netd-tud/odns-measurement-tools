package scanner

import (
	"compress/gzip"
	"dns_tools/config"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/layers"
)

const Response_timeout = 10 * time.Second

// Follow_up is one question/RD variant. Its metadata is immutable after sending.
type Follow_up struct {
	Parent_id           uint32
	Query_index         int
	Initial_response_ip net.IP
	Target_ip           net.IP
	Query               config.Follow_up_query
	RD                  bool
	Sent                time.Time
	owner               *Follow_ups
	cleanup             func(string)
}

type Follow_ups struct {
	mu       sync.Mutex
	queries  []config.Follow_up_query
	protocol string
	queue    chan *Follow_up
	pending  map[*Follow_up]bool
	writer   *csv.Writer
	zip      *gzip.Writer
	file     *os.File
	closed   bool
	senders  sync.WaitGroup
	handlers atomic.Int64
}

func Follow_up_path(outpath string) string {
	return strings.TrimSuffix(strings.TrimSuffix(outpath, ".gz"), ".csv") + "_followups.csv.gz"
}

func (bs *Base_scanner) Start_followups(outpath, protocol string, send func(*Follow_up)) {
	if len(config.Cfg.Follow_up_queries) == 0 {
		return
	}
	f, err := os.Create(Follow_up_path(outpath))
	if err != nil {
		panic(err)
	}
	z := gzip.NewWriter(f)
	cw := csv.NewWriter(z)
	cw.Comma = ';'
	if err := cw.Write([]string{"parent_id", "query_index", "initial_response_ip", "target_ip", "response_ip", "protocol", "qname", "qtype", "qclass", "request_rd", "timestamp_request", "timestamp_response", "status", "rcode", "txt_json", "dns_response_base64"}); err != nil {
		panic(err)
	}
	bs.Followups = &Follow_ups{
		queries:  append([]config.Follow_up_query(nil), config.Cfg.Follow_up_queries...),
		protocol: protocol, queue: make(chan *Follow_up, 1024), pending: make(map[*Follow_up]bool),
		writer: cw, zip: z, file: f,
	}
	bs.Followups.senders.Add(int(config.Cfg.Number_routines))
	bs.Wg.Add(2)
	go func() {
		defer bs.Wg.Done()
		for {
			select {
			case probe := <-bs.Followups.queue:
				if config.Cfg.Pkts_per_sec > 0 {
					bs.Send_limiter.Take()
				}
				select {
				case <-bs.Stop_chan:
					return
				default:
				}
				bs.Followups.mu.Lock()
				probe.Sent = time.Now()
				bs.Followups.mu.Unlock()
				send(probe)
			case <-bs.Stop_chan:
				return
			}
		}
	}()
	go func() {
		defer bs.Wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				bs.Followups.expire(now)
			case <-bs.Stop_chan:
				return
			}
		}
	}()
}

// On_complete registers protocol-state cleanup before a probe is sent.
func (p *Follow_up) On_complete(cleanup func(string)) bool {
	f := p.owner
	f.mu.Lock()
	active := f.pending[p] && !f.closed
	if active {
		p.cleanup = cleanup
	}
	f.mu.Unlock()
	if !active {
		cleanup("timeout")
	}
	return active
}

func (f *Follow_ups) expire(now time.Time) {
	f.mu.Lock()
	var expired []*Follow_up
	for probe := range f.pending {
		if !probe.Sent.IsZero() && !now.Before(probe.Sent.Add(Response_timeout)) {
			expired = append(expired, probe)
		}
	}
	f.mu.Unlock()
	for _, probe := range expired {
		probe.Complete("timeout", nil, nil, nil)
	}
}

func (bs *Base_scanner) Track_followup_handler() func() {
	f := bs.Followups
	if f == nil {
		return func() {}
	}
	f.handlers.Add(1)
	return func() { f.handlers.Add(-1) }
}

func (bs *Base_scanner) Followup_sender_done() {
	if bs.Followups != nil {
		bs.Followups.senders.Done()
	}
}

// Wait_followups extends the existing end-of-scan grace period only when enabled.
// Primary scans keep their original timeout and result-writing behavior.
func (bs *Base_scanner) Wait_followups() {
	f := bs.Followups
	if f == nil {
		return
	}
	close(bs.Ip_chan)
	f.senders.Wait()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		bs.Scan_data.Mu.Lock()
		empty := len(bs.Scan_data.Items) == 0
		bs.Scan_data.Mu.Unlock()
		if empty && f.idle() && f.handlers.Load() == 0 && len(bs.Write_chan) == 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-bs.Stop_chan:
			return
		}
	}
}

// Schedule_followups is called once for an accepted initial response, outside scan-data locks.
func (bs *Base_scanner) Schedule_followups(id uint32, target, response net.IP) {
	f := bs.Followups
	if f == nil {
		return
	}
	for _, blocked := range bs.Blocked_nets {
		if blocked.Contains(target) {
			return
		}
	}
	for i, query := range f.queries {
		variants := []bool{true}
		if !target.Equal(response) {
			variants = append(variants, false)
		}
		for _, rd := range variants {
			probe := &Follow_up{Parent_id: id, Query_index: i, Initial_response_ip: append(net.IP(nil), response...), Target_ip: append(net.IP(nil), target...), Query: query, RD: rd, owner: f}
			f.mu.Lock()
			if f.closed {
				f.mu.Unlock()
				return
			}
			f.pending[probe] = true
			f.mu.Unlock()
			select {
			case f.queue <- probe:
			case <-bs.Stop_chan:
				return
			}
		}
	}
}

func (p *Follow_up) Complete(status string, ip net.IP, dns *layers.DNS, payload []byte) {
	if p == nil {
		return
	}
	f := p.owner
	f.mu.Lock()
	if !f.pending[p] || f.closed {
		f.mu.Unlock()
		return
	}
	rcode, responseIP, received, txt, raw := "", "", "", "", ""
	if dns != nil {
		rcode = strconv.Itoa(int(dns.ResponseCode))
		responseIP, received = ip.String(), time.Now().UTC().Format(time.RFC3339Nano)
		records := make([][]string, 0)
		for _, rr := range dns.Answers {
			if rr.Type == layers.DNSTypeTXT {
				segments := make([]string, 0, len(rr.TXTs))
				for _, segment := range rr.TXTs {
					segments = append(segments, string(segment))
				}
				records = append(records, segments)
			}
		}
		encoded, err := json.Marshal(records)
		if err != nil {
			panic(err)
		}
		txt, raw = string(encoded), base64.StdEncoding.EncodeToString(payload)
	}
	rd := "0"
	if p.RD {
		rd = "1"
	}
	if err := f.writer.Write([]string{
		strconv.FormatUint(uint64(p.Parent_id), 10), strconv.Itoa(p.Query_index), p.Initial_response_ip.String(), p.Target_ip.String(), responseIP,
		f.protocol, p.Query.Name, p.Query.Type, p.Query.Class, rd, p.Sent.UTC().Format(time.RFC3339Nano), received, status, rcode, txt, raw,
	}); err != nil {
		panic(err)
	}
	delete(f.pending, p)
	cleanup := p.cleanup
	f.mu.Unlock()
	if cleanup != nil {
		cleanup(status)
	}
}

func (f *Follow_ups) idle() bool {
	if f == nil {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending) == 0
}

func (f *Follow_ups) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.writer.Flush()
	if err := f.writer.Error(); err != nil {
		panic(err)
	}
	if err := f.zip.Close(); err != nil {
		panic(err)
	}
	if err := f.file.Close(); err != nil {
		panic(err)
	}
}

// Match_question tolerates omitted questions in DNS error responses.
func Match_question(dns *layers.DNS, question layers.DNSQuestion) bool {
	if !dns.QR || dns.OpCode != layers.DNSOpCodeQuery {
		return false
	}
	if len(dns.Questions) == 0 {
		return true
	}
	if len(dns.Questions) != 1 {
		return false
	}
	q := dns.Questions[0]
	return q.Type == question.Type && q.Class == question.Class && strings.EqualFold(strings.TrimSuffix(string(q.Name), "."), strings.TrimSuffix(string(question.Name), "."))
}
