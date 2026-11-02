package scanner

import (
	"container/heap"
	"time"
)

type followup_dispatch struct {
	probe *Follow_up
	at    time.Time
}

type followup_target struct {
	ip      string
	next    time.Time
	queries []*Follow_up
	waiting *Follow_up
}

type followup_targets []*followup_target

func (h followup_targets) Len() int           { return len(h) }
func (h followup_targets) Less(i, j int) bool { return h[i].next.Before(h[j].next) }
func (h followup_targets) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *followup_targets) Push(x any)        { *h = append(*h, x.(*followup_target)) }
func (h *followup_targets) Pop() any {
	last := len(*h) - 1
	x := (*h)[last]
	(*h)[last] = nil
	*h = (*h)[:last]
	return x
}

// One timer schedules all target IPs; a cooling-down IP never blocks another IP.
func (bs *Base_scanner) send_spaced_followups(interval time.Duration, send func(*Follow_up)) {
	f := bs.Followups
	targets := make(map[string]*followup_target)
	ready := &followup_targets{}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		var tick <-chan time.Time
		if ready.Len() > 0 {
			timer.Reset(time.Until((*ready)[0].next))
			tick = timer.C
		}
		select {
		case probe := <-f.queue:
			ip := probe.Target_ip.String()
			target := targets[ip]
			if target == nil {
				target = &followup_target{ip: ip}
				targets[ip] = target
				heap.Push(ready, target)
			}
			target.queries = append(target.queries, probe)
		case <-f.dispatch_ready:
			f.mu.Lock()
			events := f.dispatched
			f.dispatched = nil
			f.mu.Unlock()
			for _, event := range events {
				target := targets[event.probe.Target_ip.String()]
				if target != nil && target.waiting == event.probe {
					target.waiting = nil
					target.next = event.at.Add(interval)
					heap.Push(ready, target)
				}
			}
		case <-tick:
			target := heap.Pop(ready).(*followup_target)
			if len(target.queries) == 0 {
				delete(targets, target.ip)
				break
			}
			probe := target.queries[0]
			target.queries[0] = nil
			target.queries = target.queries[1:]
			target.waiting = probe
			send(probe)
		case <-bs.Stop_chan:
			return
		}
		timer.Stop()
	}
}
