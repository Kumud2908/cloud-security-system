package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

var maliciousPatterns = []string{
	" or ",
	" and ",
	" union ",
	" select ",
	" drop ",
	" insert ",
	" delete ",
	"--",
	";",
	"<script>",
	"</script>",
	"../",
	"||",
	"&&",
}

func WAFMiddleware(c *fiber.Ctx) error {

	// combine request body, path, and query
	requestData := strings.ToLower(
		string(c.Body()) +
			c.Path() +
			c.Context().QueryArgs().String(),
	)

	for _, pattern := range maliciousPatterns {

		if strings.Contains(requestData, pattern) {

			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Blocked by Web Application Firewall",
			})
		}
	}

	return c.Next()
}
