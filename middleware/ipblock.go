package middleware

import (
	"github.com/Kumud2908/cloud-security-system/security"

	"github.com/gofiber/fiber/v2"
)

var ThreatEngine *security.ThreatEngine

func SetThreatEngine(engine *security.ThreatEngine) {
	ThreatEngine = engine
}

func IPBlockMiddleware(c *fiber.Ctx) error {

	ip := c.IP()

	if ThreatEngine != nil && ThreatEngine.IsIPBlocked(ip) {

		return c.Status(403).JSON(fiber.Map{
			"error": "IP blocked due to suspicious activity",
		})
	}

	return c.Next()
}
