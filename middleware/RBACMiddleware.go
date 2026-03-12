package middleware

import (
	"strings"

	"github.com/Kumud2908/cloud-security-system/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
)

func RoleMiddleware(requiredRole string) fiber.Handler {

	return func(c *fiber.Ctx) error {

		auth := c.Get("Authorization")

		if auth == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "Missing token")
		}

		tokenString := strings.TrimPrefix(auth, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return utils.SecretKey, nil
		})

		if err != nil || !token.Valid {
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid token")
		}

		claims := token.Claims.(jwt.MapClaims)

		role := claims["role"].(string)

		if role != requiredRole {
			return fiber.NewError(fiber.StatusForbidden, "Insufficient permissions")
		}

		return c.Next()
	}
}

// // yet to be merged
// func AdaptiveRateLimiter(redisClient *redis.Client) fiber.Handler {

// 	return func(c *fiber.Ctx) error {

// 		ip := c.IP()

// 		key := "rate_limit:" + ip

// 		count, _ := redisClient.Incr(c.Context(), key).Result()

// 		redisClient.Expire(c.Context(), key, 10*time.Second)

// 		// Default limit
// 		limit := int64(20)

// 		// If IP already suspicious → reduce limit
// 		failuresKey := "failed_ip:" + ip

// 		failures, _ := redisClient.Get(c.Context(), failuresKey).Int64()

// 		if failures > 3 {
// 			limit = 5
// 		}

// 		if count > limit {

// 			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
// 				"error": "Too many requests",
// 				"limit": strconv.FormatInt(limit, 10),
// 			})

// 		}

// 		return c.Next()
// 	}
// }
