package global

import (
	"math/big"
	"net"
	"sync/atomic"
)

var PublicKey = ""
var PrivateKey = ""
var PrivateKeyBigInt *big.Int = new(big.Int)
var Uint = "1000000000000000000"
var LocalPort = 63259

// var ServerHost = "127.0.0.1"
var ServerHost = "dash.broker-chain.com"
var ProxyServerHost = "dash.broker-chain.com"

// var ServerHost = "127.0.0.1"
// var ProxyServerHost = "127.0.0.1"
var ServerPort = "56741"
var ServerForwardPort = "56743"
var MyIp = ""

var Conn net.Conn

var Version = "1.0.4"

var Senior atomic.Bool
var Randomstr = ""
