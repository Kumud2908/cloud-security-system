package main

import (
	"crypto/tls"

	"github.com/valyala/fasthttp"

	"time"

	"github.com/Kumud2908/cloud-security-system/controllers"
	"github.com/Kumud2908/cloud-security-system/monitoring"
	"github.com/Kumud2908/cloud-security-system/security"

	"context"
	"log"

	"github.com/Kumud2908/cloud-security-system/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var ctx context.Context
var err error
var client *mongo.Client
var MongoUri string = "mongodb+srv://sagarkumud561_db_user:MV0swi2dPuVpi3NN@cluster0.3xjbpx4.mongodb.net/"
var userController *controllers.UserController
var securityCollection *mongo.Collection
var securityLogger *monitoring.SecurityLogger

// The init function
func init() {
	ctx = context.Background()
	//Connecting to MongoDB
	client, err = mongo.Connect(ctx,
		options.Client().ApplyURI(MongoUri))
	if err = client.Ping(context.TODO(),
		readpref.Primary()); err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB")

	//set up redis client

	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0})
	status := redisClient.Ping(ctx)
	log.Println(status)
	threatEngine := security.NewThreatEngine(redisClient, ctx)

	middleware.SetThreatEngine(threatEngine)

	securityCollection = client.Database("auth-server").Collection("security_events")
	securityLogger = monitoring.NewSecurityLogger(securityCollection, ctx)
	collection := client.Database("auth-server").Collection("users")
	userController = controllers.NewUserController(
		collection,
		ctx,
		redisClient,
		threatEngine,
		securityLogger,
	)

}

func main() {
	//Create a new router
	app := fiber.New()
	//Configure the router
	app.Use(logger.New())
	// Configure the port

	app.Use(limiter.New(limiter.Config{
		Max:        10,
		Expiration: 10 * time.Second,
	}))
	app.Use(middleware.IPBlockMiddleware)
	app.Use(middleware.WAFMiddleware)

	app.Post("/signup", userController.CreateUser)
	app.Post("/updateRole", middleware.RoleMiddleware("admin"), userController.UpdateUserRole)
	app.Post("/login", userController.Login)
	app.Get("/security/events", middleware.RoleMiddleware("admin"), func(c *fiber.Ctx) error {

		cursor, err := securityCollection.Find(ctx, bson.M{})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to fetch security events",
			})
		}
		defer cursor.Close(ctx)

		var events []monitoring.SecurityEvent

		cursor.All(ctx, &events)

		return c.JSON(events)
	})
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	log.Println("Server is running")
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	server := &fasthttp.Server{
		Handler:   app.Handler(),
		TLSConfig: tlsConfig,
	}

	log.Println("Server running securely on https://localhost:3000")

	err := server.ListenAndServeTLS(":3000", "cert.pem", "key.pem")
	if err != nil {
		log.Fatal("Server failed:", err)
	}
}
