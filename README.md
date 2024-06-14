# redis-ebpf
Redis Observability using eBPF

In order to try it out locally:

- Run eBPF program using
  ```
  go generate
  go build
  sudo ./redis
  ```
- Run the Redis Container using
  ```
  docker run -d --name my-redis-stack -p 6379:6379  redis/redis-stack-server:latest
  ```
- Run client inside `/test` using 
  ```
  go run client.go
  ```
- In another shell, inspect eBPF program logs using
  ```
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```
