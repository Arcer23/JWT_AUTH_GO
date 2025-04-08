package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DBinstance initializes and returns a MongoDB client.
func DBinstance() *mongo.Client {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error while loading the .env file")
	}

	MongoDb := os.Getenv("MONGODB_URL")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(MongoDb))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB")

	return client
}

// Client is a global MongoDB client instance.
var Client *mongo.Client = DBinstance()

// OpenCollection returns a collection from the specified MongoDB database.
func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	// Replace "cluster0" with the actual database name
	return client.Database("cluster0").Collection(collectionName)
}
