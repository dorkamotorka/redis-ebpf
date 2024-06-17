package main

import (
    "context"
    "fmt"
    "log"
    "time"

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

    key := "name"
    initialValue := "Ddosify"
    updatedValue := "Anteon"

    var totalSetTime, totalGetTime, totalUpdateTime, totalDelTime time.Duration
    const repeat = 10000

    for i := 0; i < repeat; i++ {
        // SET initial value
        start := time.Now()
        err := rdb.Set(ctx, key, initialValue, 0).Err()
        elapsed := time.Since(start)
        totalSetTime += elapsed

        if err != nil {
            log.Fatalf("Could not set key: %v", err)
        }

        // UPDATE value
        start = time.Now()
        err = rdb.Set(ctx, key, updatedValue, 0).Err()
        elapsed = time.Since(start)
        totalUpdateTime += elapsed
        if err != nil {
            log.Fatalf("Could not update key: %v", err)
        }

        // GET key
        start = time.Now()
        val, err := rdb.Get(ctx, key).Result()
        elapsed = time.Since(start)
        totalGetTime += elapsed
        if err != nil {
            log.Fatalf("Could not get key: %v", err)
        }
        if val != updatedValue {
            log.Fatalf("Expected value: %s, but got: %s", updatedValue, val)
        }

        // DELETE key
        start = time.Now()
        err = rdb.Del(ctx, key).Err()
        elapsed = time.Since(start)
        totalDelTime += elapsed

        if err != nil {
            log.Fatalf("Could not delete keys: %v", err)
        }
    }

    fmt.Printf("Average SET latency: %v\n", totalSetTime/time.Duration(repeat))
    fmt.Printf("Average UPDATE latency: %v\n", totalUpdateTime/time.Duration(repeat))
    fmt.Printf("Average GET latency: %v\n", totalGetTime/(2*time.Duration(repeat)))
    fmt.Printf("Average DEL latency: %v\n", totalDelTime/time.Duration(repeat))
}