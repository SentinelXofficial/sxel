package core

import "time"

// RateLimiter is a simple token-bucket rate limiter backed by a goroutine.
// Wait() blocks until a token is available.  Call Close() to stop the
// background goroutine when the limiter is no longer needed.
type RateLimiter struct {
	tokens chan struct{}
	done   chan struct{}
}

// newRateLimiter creates a RateLimiter that allows rps requests per second.
// The burst capacity equals rps (one second's worth of tokens).
func NewRateLimiter(rps int) *RateLimiter {
	rl := &RateLimiter{
		tokens: make(chan struct{}, rps),
		done:   make(chan struct{}),
	}
	// Pre-fill the bucket so the first burst doesn't stall.
	for i := 0; i < rps; i++ {
		rl.tokens <- struct{}{}
	}
	interval := time.Second / time.Duration(rps)
	go func() {
		for {
			select {
			case <-rl.done:
				return
			default:
				time.Sleep(interval)
				select {
				case rl.tokens <- struct{}{}:
				default: // bucket full — discard token
				}
			}
		}
	}()
	return rl
}

// Wait blocks until the rate limiter grants a token.
func (rl *RateLimiter) Wait() {
	if rl != nil {
		<-rl.tokens
	}
}

// Close stops the background goroutine.  Safe to call on a nil RateLimiter.
func (rl *RateLimiter) Close() {
	if rl != nil {
		close(rl.done)
	}
}

