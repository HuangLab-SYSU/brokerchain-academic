package networks

import (
	"blockEmulator/global"
	"blockEmulator/message"
	"blockEmulator/params"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	rand2 "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"math/rand"

	"golang.org/x/time/rate"
)

var connMaplock sync.Mutex
var connectionPool = make(map[string]net.Conn, 0)

// network params.
var randomDelayGenerator *rand.Rand
var rateLimiterDownload *rate.Limiter
var rateLimiterUpload *rate.Limiter

// Define the latency, jitter and bandwidth here.
// Init tools.
func InitNetworkTools() {
	// avoid wrong params.
	if params.Delay < 0 {
		params.Delay = 0
	}
	if params.JitterRange < 0 {
		params.JitterRange = 0
	}
	if params.Bandwidth < 0 {
		params.Bandwidth = 0x7fffffff
	}

	// generate the random seed.
	randomDelayGenerator = rand.New(rand.NewSource(time.Now().UnixMicro()))
	// Limit the download rate
	rateLimiterDownload = rate.NewLimiter(rate.Limit(params.Bandwidth), params.Bandwidth)
	// Limit the upload rate
	rateLimiterUpload = rate.NewLimiter(rate.Limit(params.Bandwidth), params.Bandwidth)
}

type ConReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}

func SignECDSA(private *big.Int, data string) (string, string, error) {
	privateKey := &ecdsa.PrivateKey{}
	privateKey.Curve = elliptic.P256()
	privateKey.D = private
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand2.Reader, privateKey, hash[:])
	if err != nil {
		return "", "", err
	}
	r1 := hex.EncodeToString(r.Bytes())
	s1 := hex.EncodeToString(s.Bytes())
	return r1, s1, nil
}

var Lock sync.Mutex
var lastbeattime = time.Now()

func TcpDial(context []byte, addr string) {
	Lock.Lock()
	defer Lock.Unlock()
	if addr == global.MyIp {
		conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(global.LocalPort))
		if err != nil {
			log.Println("Connect error", err)
			return
		}
		conn.Write(append(context, '\n'))
		conn.Close()
		return
	}

	bytes1 := message.MergeMessage2(addr, context)
	for {
		_, err := global.Conn.Write(append(bytes1, '\n'))
		if err == nil {
			break
		}
		for {
			randstr := uuid.New().String()
			sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, randstr)
			conreq := ConReq{
				PublicKey: global.PublicKey,
				RandomStr: randstr,
				Sign1:     sign1,
				Sign2:     sign2,
			}
			marshal, _ := json.Marshal(conreq)
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			conn, err1 := dialer.Dial("tcp", global.ServerHost+":"+global.ServerForwardPort)

			if err1 != nil {
				//log.Println("Connect error", err1)
			} else {
				conn.(*net.TCPConn).SetKeepAlive(true)
				global.Conn = conn

				bytes2 := message.MergeMessage2("auth", marshal)
				global.Conn.Write(append(bytes2, '\n'))
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	//if err := (global.Conn).(*net.TCPConn).SetKeepAlive(true); err != nil {
	//	for  {
	//		randstr := uuid.New().String()
	//		sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, randstr)
	//		conreq := ConReq{
	//			PublicKey: global.PublicKey,
	//			RandomStr: randstr,
	//			Sign1:     sign1,
	//			Sign2:     sign2,
	//		}
	//		marshal, _ := json.Marshal(conreq)
	//		dialer := &net.Dialer{Timeout:  3 * time.Second}
	//		conn, err1 := dialer.Dial("tcp", global.ServerHost+":"+global.ServerForwardPort)
	//
	//		if err1 != nil {
	//			log.Println("Connect error", err1)
	//		}else {
	//			conn.(*net.TCPConn).SetKeepAlive(true)
	//			global.Conn = conn
	//
	//			bytes2:=message.MergeMessage2("auth",marshal)
	//			global.Conn.Write(append(bytes2, '\n'))
	//			break
	//		}
	//		time.Sleep(100*time.Millisecond)
	//	}
	//}

	//if time.Since(lastbeattime).Seconds() >= 15{
	//	bytes2:=message.MergeMessage2("beat",[]byte{1})
	//	global.Conn.Write(append(bytes2, '\n'))
	//	lastbeattime = time.Now()
	//}

	return
	go func() {
		// simulate the delay
		thisDelay := params.Delay
		if params.JitterRange != 0 {
			thisDelay = randomDelayGenerator.Intn(params.JitterRange) - params.JitterRange/2 + params.Delay
		}
		time.Sleep(time.Millisecond * time.Duration(thisDelay))

		connMaplock.Lock()
		defer connMaplock.Unlock()

		var err error
		var conn net.Conn // Define conn here

		// if this connection is not built, build it.
		if c, ok := connectionPool[addr]; ok {
			if tcpConn, tcpOk := c.(*net.TCPConn); tcpOk {
				if err := tcpConn.SetKeepAlive(true); err != nil {
					delete(connectionPool, addr) // Remove if not alive
					conn, err = net.Dial("tcp", addr)
					if err != nil {
						log.Println("Reconnect error", err)
						return
					}
					connectionPool[addr] = conn
				} else {
					conn = c // Use the existing connection
				}
			}
		} else {
			conn, err = net.Dial("tcp", addr)
			if err != nil {
				log.Println("Connect error", err)
				return
			}
			connectionPool[addr] = conn
		}

		writeToConn(append(context, '\n'), conn, rateLimiterUpload)
	}()
}

// Broadcast sends a message to multiple receivers, excluding the sender.
func Broadcast(sender string, receivers []string, msg []byte) {
	for _, ip := range receivers {
		if ip == sender {
			continue
		}
		go TcpDial(msg, ip)
	}
}

// CloseAllConnInPool closes all connections in the connection pool.
func CloseAllConnInPool() {
	connMaplock.Lock()
	defer connMaplock.Unlock()

	for _, conn := range connectionPool {
		conn.Close()
	}
	connectionPool = make(map[string]net.Conn) // Reset the pool
}

// ReadFromConn reads data from a connection.
func ReadFromConn(addr string) {
	conn := connectionPool[addr]

	// new a conn reader
	connReader := NewConnReader(conn, rateLimiterDownload)

	buffer := make([]byte, 1024)
	var messageBuffer bytes.Buffer

	for {
		n, err := connReader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Println("Read error for address", addr, ":", err)
			}
			break
		}

		// add message to buffer
		messageBuffer.Write(buffer[:n])

		// handle the full message
		for {
			message, err := readMessage(&messageBuffer)
			if err == io.ErrShortBuffer {
				// continue to load if buffer is short
				break
			} else if err == nil {
				// log the full message
				log.Println("Received from", addr, ":", message)
			} else {
				// handle other errs
				log.Println("Error processing message for address", addr, ":", err)
				break
			}
		}
	}
}

func readMessage(buffer *bytes.Buffer) (string, error) {
	message, err := buffer.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(message), nil
}
