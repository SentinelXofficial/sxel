package core

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mu        sync.Mutex
	lim       *rate.Limiter
	adapted   bool
	minRate   float64
	initRate  rate.Limit
	lastAdapt time.Time
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		rps = 1
	}
	l := &RateLimiter{initRate: rate.Limit(rps), minRate: 0.25}
	l.lim = rate.NewLimiter(l.initRate, rps)
	return l
}

func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	if rl.adapted && time.Since(rl.lastAdapt) > 30*time.Second {
		rl.lim.SetLimit(rl.initRate)
		rl.lim.SetBurst(int(rl.initRate))
		rl.adapted = false
	}
	rl.mu.Unlock()
	rl.lim.Wait(context.Background())
}

func (rl *RateLimiter) Adapt429() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	cur := rl.lim.Limit()
	next := cur / 2
	if next < rate.Limit(rl.minRate) {
		next = rate.Limit(rl.minRate)
	}
	if next != cur {
		rl.lim.SetLimit(next)
		rl.lim.SetBurst(2)
		rl.adapted = true
		rl.lastAdapt = time.Now()
	}
	rl.mu.Unlock()
	time.Sleep(2 * time.Second)
}

func (rl *RateLimiter) Close() {}
