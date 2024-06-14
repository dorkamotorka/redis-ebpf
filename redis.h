// Redis serialization protocol (RESP) specification
// https://redis.io/docs/reference/protocol-spec/

// A client sends the Redis server an array consisting of only bulk strings.
// A Redis server replies to clients, sending any valid RESP data type as a reply.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_PAYLOAD_SIZE 1024

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_REDIS	1

#define STATUS_SUCCESS 1
#define STATUS_ERROR 2
#define STATUS_UNKNOWN 3

#define METHOD_UNKNOWN 0
#define METHOD_REDIS_COMMAND     1
#define METHOD_REDIS_PUSHED_EVENT 2
#define METHOD_REDIS_PING     3


struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct socket_key {
    __u64 fd;
    __u32 pid;
    __u8 is_tls;
};

struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_enter_read{
    struct trace_entry ent;
    int __syscall_nr;
    unsigned long int fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_exit_read {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
    __u32 seq;
    __u32 tid;
};

struct l7_event {
    __u64 fd;
    __u64 write_time_ns;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 failed;
    __u8 is_tls;
    __u32 seq;
    __u32 tid;
};

struct trace_event_raw_sys_exit_recvfrom {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

static __always_inline
int is_redis_ping(char *buf, __u64 buf_size) {
    // *1\r\n$4\r\nping\r\n
    if (buf_size < 14) {
        return 0;
    }
    char b[14];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }

    if (b[0] != '*' || b[1] != '1' || b[2] != '\r' || b[3] != '\n' || b[4] != '$' || b[5] != '4' || b[6] != '\r' || b[7] != '\n') {
        return 0;
    }

    if (b[8] != 'p' || b[9] != 'i' || b[10] != 'n' || b[11] != 'g' || b[12] != '\r' || b[13] != '\n') {
        return 0;
    }

    return STATUS_SUCCESS;
}

static __always_inline
int is_redis_pong(char *buf, __u64 buf_size) {
    // *2\r\n$4\r\npong\r\n$0\r\n\r\n
    if (buf_size < 14) {
        return 0;
    }
    char b[14];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }

    if (b[0] != '*' || b[1] < '0' || b[1] > '9' || b[2] != '\r' || b[3] != '\n' || b[4] != '$' || b[5] != '4' || b[6] != '\r' || b[7] != '\n') {
        return 0;
    }

    if (b[8] != 'p' || b[9] != 'o' || b[10] != 'n' || b[11] != 'g' || b[12] != '\r' || b[13] != '\n') {
        return 0;
    }

    return STATUS_SUCCESS;
}

static __always_inline
int is_redis_command(char *buf, __u64 buf_size) {
    //*3\r\n$7\r\nmessage\r\n$10\r\nmy_channel\r\n$13\r\nHello, World!\r\n
    if (buf_size < 11) {
        return 0;
    }
    char b[11];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }
    // Clients send commands to the Redis server as RESP arrays
    // * is the array prefix
    // latter is the number of elements in the array
    // check if it is a RESP array
    if (b[0] != '*' || b[1] < '0' || b[1] > '9') {
        return 0;
    }
    // Check if command is not "message", message command is used for pub/sub by server to notify sub.
    // CLRF(\r\n) is the seperator in RESP protocol
    if (b[2] == '\r' && b[3] == '\n') {
        if (b[4]=='$' && b[5] == '7' && b[6] == '\r' && b[7] == '\n' && b[8] == 'm' && b[9] == 'e' && b[10] == 's'){
            return 0;
        }
        return 1;
    }

    // Array length can exceed 9, so check if the second byte is a digit
    if (b[2] >= '0' && b[2] <= '9' && b[3] == '\r' && b[4] == '\n') {
        if (b[5]=='$' && b[6] == '7' && b[7] == '\r' && b[8] == '\n' && b[9] == 'm' && b[10] == 'e'){
            return 0;
        }
        return 1;
    }


    return 0;
}

static __always_inline
__u32 is_redis_pushed_event(char *buf, __u64 buf_size){
    if (buf_size < 17) {
        return 0;
    }

    char b[17];
    if (bpf_probe_read(&b, sizeof(b), (void *)((char *)buf)) < 0) {
        return 0;
    }

    //*3\r\n$7\r\nmessage\r\n$10\r\nmy_channel\r\n$13\r\nHello, World!\r\n
    // message received from the Redis server

    // In RESP3 protocol, the first byte of the pushed event is '>'
    // whereas in RESP2 protocol, the first byte is '*'
    if ((b[0] != '>' && b[0] != '*') || b[1] < '0' || b[1] > '9'){
        return 0;
    }

    // CLRF(\r\n) is the seperator in RESP protocol
    if (b[2] == '\r' && b[3] == '\n') {
        if (b[4]=='$' && b[5] == '7' && b[6] == '\r' && b[7] == '\n' && b[8] == 'm' && b[9] == 'e' && b[10] == 's' && b[11] == 's' && b[12] == 'a' && b[13] == 'g' && b[14] == 'e' && b[15] == '\r' && b[16] == '\n') {
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}

static __always_inline
__u32 parse_redis_response(char *buf, __u64 buf_size) {
    char type;
    if (bpf_probe_read(&type, sizeof(type), (void *)((char *)buf)) < 0) {
        return STATUS_UNKNOWN;
    }
    char end[2]; // must end with \r\n
    
    if (bpf_probe_read(&end, sizeof(end), (void *)((char *)buf+buf_size-2)) < 0) {
        return 0;
    }

    if (end[0] != '\r' || end[1] != '\n') {
        return STATUS_UNKNOWN;
    }

    // Accepted since RESP2
    // Array | Integer | Bulk String | Simple String  
    if (type == '*' || type == ':' || type == '$' || type == '+'
    ) {
        return STATUS_SUCCESS;
    }

    // https://redis.io/docs/latest/develop/reference/protocol-spec/#simple-errors
    // Accepted since RESP2
    // Error
    if (type == '-') {
        return STATUS_ERROR;
    }

    // Accepted since RESP3
    // Null | Boolean | Double | Big Numbers | Verbatim String | Maps | Set 
    if (type == '_' || type == '#' || type == ',' || type =='(' || type == '=' || type == '%' || type == '~') {
        return STATUS_SUCCESS;
    }


    // Accepted since RESP3
    // Bulk Errors
    if (type == '!') {
        return STATUS_ERROR;
    }

    return STATUS_UNKNOWN;
}