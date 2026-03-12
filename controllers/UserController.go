package controllers

import (
	"context"
	"log"
	"time"

	"github.com/Kumud2908/cloud-security-system/models"
	"github.com/Kumud2908/cloud-security-system/monitoring"
	"github.com/Kumud2908/cloud-security-system/security"
	"github.com/Kumud2908/cloud-security-system/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserController struct {
	collection     *mongo.Collection
	ctx            context.Context
	redisClient    *redis.Client
	threatEngine   *security.ThreatEngine
	securityLogger *monitoring.SecurityLogger
}
type Signup struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AddPermission struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func NewUserController(
	collection *mongo.Collection,
	ctx context.Context,
	redisClient *redis.Client,
	threatEngine *security.ThreatEngine,
	logger *monitoring.SecurityLogger,
) *UserController {

	return &UserController{
		collection:     collection,
		ctx:            ctx,
		redisClient:    redisClient,
		threatEngine:   threatEngine,
		securityLogger: logger,
	}
}

func (uc *UserController) CreateUser(c *fiber.Ctx) error {
	//Create a new signupReq Object
	signupReq := new(Signup)
	//Parse data into the object
	if err := c.BodyParser(signupReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	// Hash the password for the user
	hashedPassword, err := utils.HashPassword(signupReq.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Server Error")
	}

	// Create a new user
	user := new(models.User)
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.Username = signupReq.Username
	user.Password = hashedPassword
	user.Role = "viewer"
	//Save the user in mongoDB

	if signupReq.Username == "" || signupReq.Password == "" {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"Username and password required",
		)
	}
	count, err := uc.collection.CountDocuments(
		uc.ctx,
		bson.M{"username": signupReq.Username},
	)

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "DB Error")
	}

	if count > 0 {
		return fiber.NewError(fiber.StatusBadRequest, "User already exists")
	}
	savedUser, err := uc.collection.InsertOne(uc.ctx, user)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Unable to save user")
	}
	log.Println("User Created", savedUser)
	return c.JSON(fiber.Map{"message": "Success"})
}

func (uc *UserController) Login(c *fiber.Ctx) error {

	ip := c.IP()

	signupReq := new(Signup)
	if err := c.BodyParser(signupReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	username := signupReq.Username

	// 🔴 Check if IP is blocked
	if uc.threatEngine.IsIPBlocked(ip) {
		utils.LogSecurityEvent("BLOCKED_IP_ACCESS", ip)
		uc.securityLogger.LogEvent("BLOCKED_IP_ACCESS", username, ip)
		return fiber.NewError(fiber.StatusForbidden, "IP Blocked")
	}

	// 🔴 Check if account locked
	if uc.threatEngine.IsLocked(username) {
		return fiber.NewError(
			fiber.StatusForbidden,
			"Account temporarily locked due to multiple failed logins",
		)
	}

	user := new(models.User)

	// 🔍 Find user
	err := uc.collection.FindOne(
		uc.ctx,
		bson.M{"username": username},
	).Decode(user)

	if err != nil {

		// record user failure
		failures := uc.threatEngine.RecordFailedLogin(username)

		// record IP failure for adaptive rate limiter
		ipFailures := uc.threatEngine.RecordIPFailure(ip)

		utils.LogSecurityEvent(
			"LOGIN_FAILED",
			username+" "+ip,
		)

		uc.securityLogger.LogEvent(
			"LOGIN_FAILED",
			username,
			ip,
		)

		// adaptive mitigation
		if failures >= 5 {

			uc.threatEngine.LockAccount(username)
			uc.threatEngine.BlockIP(ip)

			utils.LogSecurityEvent(
				"ACCOUNT_LOCKED",
				username+" "+ip,
			)

			uc.securityLogger.LogEvent(
				"ACCOUNT_LOCKED",
				username,
				ip,
			)
		}

		// if IP too suspicious → block faster
		if ipFailures >= 10 {
			uc.threatEngine.BlockIP(ip)
		}

		return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
	}

	// 🔐 Verify password
	err = utils.VerifyPassword(signupReq.Password, user.Password)

	if err != nil {

		failures := uc.threatEngine.RecordFailedLogin(username)

		ipFailures := uc.threatEngine.RecordIPFailure(ip)

		utils.LogSecurityEvent(
			"LOGIN_FAILED",
			username+" "+ip,
		)

		uc.securityLogger.LogEvent(
			"LOGIN_FAILED",
			username,
			ip,
		)

		if failures >= 5 {

			uc.threatEngine.LockAccount(username)
			uc.threatEngine.BlockIP(ip)

			utils.LogSecurityEvent(
				"ACCOUNT_LOCKED",
				username+" "+ip,
			)

			uc.securityLogger.LogEvent(
				"ACCOUNT_LOCKED",
				username,
				ip,
			)
		}

		if ipFailures >= 10 {
			uc.threatEngine.BlockIP(ip)
		}

		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized")
	}
	// 🟢 Successful login
	uc.threatEngine.ResetFailures(username)

	// 🔐 Generate JWT with role
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["username"] = user.Username
	claims["role"] = user.Role
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

	tokenString, err := token.SignedString(utils.SecretKey)

	if err != nil {

		log.Println("Error signing token:", err)

		return fiber.NewError(
			fiber.StatusInternalServerError,
			"Token generation failed",
		)
	}

	utils.LogSecurityEvent(
		"LOGIN_SUCCESS",
		username+" "+ip,
	)

	uc.securityLogger.LogEvent(
		"LOGIN_SUCCESS",
		username,
		ip,
	)

	log.Println("JWT Token:", tokenString)

	return c.JSON(fiber.Map{
		"token": tokenString,
	})
}

func (uc *UserController) TestRoute(c *fiber.Ctx) error {
	return c.SendString("Admin Test Route")
}

func (uc *UserController) UpdateUserRole(c *fiber.Ctx) error {

	username := c.Params("username")

	type RoleUpdate struct {
		Role string `json:"role"`
	}

	req := new(RoleUpdate)

	if err := c.BodyParser(req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	// Only allow predefined roles
	validRoles := map[string]bool{
		"admin":  true,
		"editor": true,
		"viewer": true,
	}

	if !validRoles[req.Role] {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid role")
	}

	_, err := uc.collection.UpdateOne(
		uc.ctx,
		bson.M{"username": username},
		bson.M{
			"$set": bson.M{
				"role": req.Role,
			},
		},
	)

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update role")
	}

	return c.JSON(fiber.Map{
		"message": "Role updated successfully",
	})
}
