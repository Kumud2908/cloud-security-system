package security

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type ThreatEngine struct {
	Redis *redis.Client
	Ctx   context.Context
}

func NewThreatEngine(redis *redis.Client, ctx context.Context) *ThreatEngine {
	return &ThreatEngine{
		Redis: redis,
		Ctx:   ctx,
	}
}

// track login failures per user
func (t *ThreatEngine) RecordFailedLogin(username string) int64 {

	key := "failed_login:" + username

	count, err := t.Redis.Incr(t.Ctx, key).Result()

	if err != nil {
		return 0
	}

	t.Redis.Expire(t.Ctx, key, 10*time.Minute)

	return count
}

// reset failures after successful login
func (t *ThreatEngine) ResetFailures(username string) {

	key := "failed_login:" + username

	t.Redis.Del(t.Ctx, key)
}

// track failures per IP
func (t *ThreatEngine) RecordIPFailure(ip string) int64 {

	key := "failed_ip:" + ip

	count, _ := t.Redis.Incr(t.Ctx, key).Result()

	t.Redis.Expire(t.Ctx, key, 10*time.Minute)

	return count
}

// lock account
func (t *ThreatEngine) LockAccount(username string) {

	key := "locked_user:" + username

	t.Redis.Set(t.Ctx, key, "1", 10*time.Minute)
}

// check account lock
func (t *ThreatEngine) IsLocked(username string) bool {

	key := "locked_user:" + username

	val, _ := t.Redis.Exists(t.Ctx, key).Result()

	return val == 1
}

// block IP
func (t *ThreatEngine) BlockIP(ip string) {

	key := "blocked_ip:" + ip

	t.Redis.Set(t.Ctx, key, "1", 2*time.Minute)
}

// only for testing purposes
func (t *ThreatEngine) UnblockIP(ip string) {

	key := "blocked_ip:" + ip

	t.Redis.Del(t.Ctx, key)
}

// check IP block
func (t *ThreatEngine) IsIPBlocked(ip string) bool {

	key := "blocked_ip:" + ip

	val, _ := t.Redis.Exists(t.Ctx, key).Result()

	return val == 1
}
