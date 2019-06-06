package ratelimiter

import (
	"sync"

	"golang.org/x/time/rate"
)

type HostRateLimitMap struct {
	hosts      map[string]*rate.Limiter
	mtx        sync.Mutex
	maxRate    rate.Limit
	burstLimit int
}

func NewHostRateLimitMap(r rate.Limit, b int) *HostRateLimitMap {
	m := &HostRateLimitMap{}
	m.hosts = make(map[string]*rate.Limiter)
	m.maxRate = r
	m.burstLimit = b
	return m
}

func (m *HostRateLimitMap) addHost(mac string) *rate.Limiter {
	limiter := rate.NewLimiter(m.maxRate, m.burstLimit)
	m.mtx.Lock()
	m.hosts[mac] = limiter
	m.mtx.Unlock()
	return limiter
}

// GetHost Returns rate limiter for host
func (m *HostRateLimitMap) GetHost(mac string) *rate.Limiter {
	m.mtx.Lock()
	limiter, exists := m.hosts[mac]
	m.mtx.Unlock()
	if !exists {
		return m.addHost(mac)
	}
	return limiter
}
