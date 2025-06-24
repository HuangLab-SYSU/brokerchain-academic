package global

import (
	"math/big"
	"net"
)

var PublicKey = ""
var PrivateKey = ""
var PrivateKeyBigInt *big.Int = new(big.Int)
var Uint = "1000000000000000000"
var LocalPort = 63259

//var ServerHost = "127.0.0.1"
var ServerHost = "academic.broker-chain.com"
var ServerPort = "56741"
var ServerForwardPort = "56743"
var MyIp = ""

var Conn net.Conn

var Version = "1.0.3"
