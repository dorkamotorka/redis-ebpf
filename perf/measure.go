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
    value := "anteon"

    var totalSetTime, totalGetTime, totalDelTime time.Duration
    const repeat = 1000

    for i := 0; i < repeat; i++ {
        start := time.Now()
        err := rdb.Set(ctx, key, value, 0).Err()
        elapsed := time.Since(start)
        totalSetTime += elapsed

        if err != nil {
            log.Fatalf("Could not set key: %v", err)
        }

        start = time.Now()
        val, err := rdb.Get(ctx, key).Result()
        elapsed = time.Since(start)
        totalGetTime += elapsed

        if err != nil {
            log.Fatalf("Could not get key: %v", err)
        }

        start = time.Now()
        err = rdb.Del(ctx, key).Err()
        elapsed = time.Since(start)
        totalDelTime += elapsed

        if err != nil {
            log.Fatalf("Could not delete keys: %v", err)
        }

        if val != value {
            log.Fatalf("Expected value: %s, but got: %s", value, val)
        }
    }

    fmt.Printf("Average SET latency: %v\n", totalSetTime/time.Duration(repeat))
    fmt.Printf("Average GET latency: %v\n", totalGetTime/time.Duration(repeat))
    fmt.Printf("Average DEL latency: %v\n", totalDelTime/time.Duration(repeat))
}
