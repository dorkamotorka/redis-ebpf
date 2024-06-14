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

    // Perform a simple PING-PONG
    pong, err := rdb.Ping(ctx).Result()
    if err != nil {
        log.Fatalf("Could not ping Redis: %v", err)
    }
    fmt.Printf("PING response: %s\n", pong)

    key := "name"
    value := "anteon"

    // Use the SET command to store a key-value pair
    err = rdb.Set(ctx, key, value, 0).Err()
    if err != nil {
        log.Fatalf("Could not set key: %v", err)
    }
    fmt.Printf("Set key: '%s', value: '%s'\n", key, value)

    // Use the GET command to retrieve the value of the key
    val, err := rdb.Get(ctx, key).Result()
    if err != nil {
        log.Fatalf("Could not get key: %v", err)
    }
    fmt.Printf("Got value for '%s': %s\n", key, val)

    // Create and manipulate a list
    listKey := "mylist"
    err = rdb.RPush(ctx, listKey, "item1", "item2", "item3").Err()
    if err != nil {
        log.Fatalf("Could not push to list: %v", err)
    }
    fmt.Printf("Added items to list '%s'\n", listKey)

    listItems, err := rdb.LRange(ctx, listKey, 0, -1).Result()
    if err != nil {
        log.Fatalf("Could not get list items: %v", err)
    }
    fmt.Printf("Items in list '%s': %v\n", listKey, listItems)

    // Create and manipulate a hash
    hashKey := "myhash"
    err = rdb.HSet(ctx, hashKey, "field1", "value1", "field2", "value2").Err()
    if err != nil {
        log.Fatalf("Could not set hash: %v", err)
    }
    fmt.Printf("Set fields in hash '%s'\n", hashKey)

    hashValues, err := rdb.HGetAll(ctx, hashKey).Result()
    if err != nil {
        log.Fatalf("Could not get hash fields: %v", err)
    }
    fmt.Printf("Fields in hash '%s': %v\n", hashKey, hashValues)

    // Clean up the keys
    err = rdb.Del(ctx, key, listKey, hashKey).Err()
    if err != nil {
        log.Fatalf("Could not delete keys: %v", err)
    }
    fmt.Println("Deleted keys")

    // Try to get the value of the deleted key
    val, err = rdb.Get(ctx, key).Result()
    if err == redis.Nil {
        fmt.Printf("Key '%s' does not exist - this is good, because we deleted it :) \n", key)
    } else if err != nil {
        log.Fatalf("Error getting key: %v", err)
    } else {
        fmt.Printf("Got value for '%s': %s\n", key, val)
    }
}