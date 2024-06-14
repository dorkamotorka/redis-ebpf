package main

// Order is important
const (
	BPF_L7_PROTOCOL_UNKNOWN = iota
	BPF_L7_PROTOCOL_REDIS
)

const (
	L7_PROTOCOL_REDIS = "REDIS"
	L7_PROTOCOL_UNKNOWN  = "UNKNOWN"
)

// Order is important
const (
	BPF_REDIS_METHOD_UNKNOWN = iota
	METHOD_REDIS_COMMAND
	METHOD_REDIS_PUSHED_EVENT
	METHOD_REDIS_PING
)

// for redis, user space
const (
	REDIS_COMMAND      = "COMMAND"
	REDIS_PUSHED_EVENT = "PUSHED_EVENT"
	REDIS_PING         = "PING"
)

type L7Event struct {
	Fd                  uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            string // L7_PROTOCOL_HTTP
	Tls                 bool   // Whether request was encrypted
	Method              string
	Payload             [1024]uint8
	PayloadSize         uint32 // How much of the payload was copied
	PayloadReadComplete bool   // Whether the payload was copied completely
	Failed              bool   // Request failed
	WriteTimeNs         uint64 // start time of write syscall
	Tid                 uint32
	Seq                 uint32 // tcp seq num
	EventReadTime       int64
}

type bpfL7Event struct {
	Fd                  uint64
	WriteTimeNs         uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	Payload             [1024]uint8
	PayloadSize         uint32
	PayloadReadComplete uint8
	Failed              uint8
	IsTls               uint8
	_                   [1]byte
	Seq                 uint32
	Tid                 uint32
	_                   [4]byte
}

// Custom types for the enumeration
type L7ProtocolConversion uint32
type RedisMethodConversion uint32

// String representation of the enumeration values
func (e L7ProtocolConversion) String() string {
	switch e {
	case BPF_L7_PROTOCOL_REDIS:
		return L7_PROTOCOL_REDIS
	case BPF_L7_PROTOCOL_UNKNOWN:
		return L7_PROTOCOL_UNKNOWN
	default:
		return "Unknown"
	}
}

// String representation of the enumeration values
func (e RedisMethodConversion) String() string {
	switch e {
	case METHOD_REDIS_COMMAND:
		return REDIS_COMMAND
	case METHOD_REDIS_PUSHED_EVENT:
		return REDIS_PUSHED_EVENT
	case METHOD_REDIS_PING:
		return REDIS_PING
	default:
		return "Unknown"
	}
}