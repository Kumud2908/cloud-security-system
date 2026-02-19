package controllers

import (
	"auth-server/models"
	"auth-server/utils"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var SecretKey = []byte("SecretKey")

type UserController struct {
	collection  *mongo.Collection
	ctx         context.Context
	redisClient *redis.Client
}
type Signup struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AddPermission struct {
	Username   string             `json:"username"`
	Permission models.Permissions `json:"permission"`
}

func NewUserController(collection *mongo.Collection, ctx context.Context, redisClient *redis.Client) *UserController {
	return &UserController{
		collection:  collection,
		ctx:         ctx,
		redisClient: redisClient,
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
	user.Permissions = make([]models.Permissions, 0)
	//Save the user in mongoDB
	savedUser, err := uc.collection.InsertOne(uc.ctx, user)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Unable to save user")
	}
	log.Println("User Created", savedUser)
	return c.JSON(fiber.Map{"message": "Success"})
}

func (uc *UserController) AddPermission(c *fiber.Ctx) error {
	addPermissionReq := new(AddPermission)
	if err := c.BodyParser(addPermissionReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	user := new(models.User)
	//Find the user
	err := uc.collection.FindOne(uc.ctx, bson.D{{"username", addPermissionReq.Username}}).Decode(&user)
	if err != nil {
		return err
	}
	log.Println("User Received", user)
	//Check if permissions for the given entity already exists
	for _, v := range user.Permissions {
		if v.Entry == addPermissionReq.Permission.Entry {
			return fiber.NewError(fiber.StatusBadRequest, "Permission already exists")
		}
	}
	//Update the permission if it doesn't exist
	uc.collection.FindOneAndUpdate(uc.ctx, bson.D{{"username", addPermissionReq.Username}}, bson.M{"$push": bson.M{"permissions": addPermissionReq.Permission}})
	return c.JSON(fiber.Map{"message": "Success"})
}

func (uc *UserController) Login(c *fiber.Ctx) error {

	signupReq := new(Signup)
	if err := c.BodyParser(signupReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	user := new(models.User)
	//Finding user
	err := uc.collection.FindOne(uc.ctx, bson.D{{"username", signupReq.Username}}).Decode(&user)
	if err != nil {
		return err
	}
	//verifying user password
	err = utils.VerifyPassword(signupReq.Password, user.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized")
	}
	//Creating has for user permissions
	objStr := fmt.Sprintf("%+v", user.Permissions)
	data := []byte(objStr)
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if err != nil {
		log.Fatal("Error:", err)
		return err
	}
	hash := hasher.Sum(nil)
	hashString := hex.EncodeToString(hash)
	//Converting the hash to a jwt token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["hash"] = hashString
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

	permissionsJSON, err := json.Marshal(user.Permissions)
	//Setting the hash based value in redis
	result, err := uc.redisClient.SetNX(uc.ctx, hashString, permissionsJSON, 0).Result()
	log.Println("ERR", err)
	log.Println("Result from redis", result)
	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		log.Fatal("Error signing token:", err)
		return err
	}
	log.Println("JWT Token:", tokenString)
	return c.JSON(fiber.Map{"token": tokenString})
}
func (uc *UserController) TestRoute(c *fiber.Ctx) error {
	return c.SendString("Admin Test Route")
}
