package main

import (
	"context"
	"fmt"
	"log"

	"github.com/go-redis/redis/v8"
)

// Create a context for the Redis operations
var ctx = context.Background()

func main() {
	// Create a new Redis client
	rdb := redis.NewClient(&redis.Options{
			Addr:     "localhost:6379", // Redis server address
			Password: "",               // No password set
			DB:       0,                // Use default DB
	})

	// Use the SET command to store a key-value pair
	err := rdb.Set(ctx, "name", "anteon", 0).Err()
	if err != nil {
			log.Fatalf("Could not set key: %v", err)
	}
	fmt.Println("Set key: 'name', value: 'anteon'")

	// Use the GET command to retrieve the value of the key
	val, err := rdb.Get(ctx, "name").Result()
	if err != nil {
			log.Fatalf("Could not get key: %v", err)
	}
	fmt.Printf("Got value for 'name': %s\n", val)

	// Use the DEL command to delete the key
	err = rdb.Del(ctx, "name").Err()
	if err != nil {
			log.Fatalf("Could not delete key: %v", err)
	}
	fmt.Println("Deleted key: 'name'")

	// Try to get the value of the deleted key
	val, err = rdb.Get(ctx, "name").Result()
	if err == redis.Nil {
			fmt.Println("Key 'key' does not exist anymore, since it was delete - this is good :)")
	} else if err != nil {
			log.Fatalf("Error getting key: %v", err)
	} else {
			fmt.Printf("Got value for 'name': %s\n", val)
	}

	fmt.Println("Client finished Succesfully...")
}