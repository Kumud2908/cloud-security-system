package utils

import "log"

func LogSecurityEvent(event string, ip string) {
	log.Printf("[SECURITY] %s from %s\n", event, ip)
}
