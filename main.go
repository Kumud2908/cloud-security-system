package main

import (
	"auth-server/controllers"
	"auth-server/middleware"
	"context"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var ctx context.Context
var err error
var client *mongo.Client
var MongoUri string = "mongodb+srv://sagarkumud561_db_user:MV0swi2dPuVpi3NN@cluster0.3xjbpx4.mongodb.net/"
var middleware1 *middleware.Middleware
var userController *controllers.UserController

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

	collection := client.Database("auth-server").Collection("users")
	userController = controllers.NewUserController(collection, ctx, redisClient)
	middleware1 = middleware.NewMiddleware(ctx, redisClient)

}

func main() {
	//Create a new router
	app := fiber.New()
	//Configure the router
	app.Use(logger.New())
	// Configure the port

	app.Post("/signup", userController.CreateUser)
	app.Post("/addPermission", userController.AddPermission)
	app.Post("/login", userController.Login)
	app.Post("/adminTestRoute", middleware1.AdminMiddlewareHandler, userController.TestRoute)
	log.Println("Server is running")
	err := app.Listen(":3000")
	if err != nil {
		log.Fatal("Error in running the server")
		return
	}
}
