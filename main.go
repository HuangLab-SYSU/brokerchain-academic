package main

import (
	"blockEmulator/build"
	"blockEmulator/global"
	"blockEmulator/networks"
	"blockEmulator/params"
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	rand2 "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// network config
	shardNum int
	nodeNum  int
	shardID  int
	nodeID   int
)

func Get(url string, data []byte) ([]byte, error) {
	req, err := http.NewRequest("GET", "http://"+global.ServerHost+":"+global.ServerPort+"/"+url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}
	return body, nil
}

func Post(url string, data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", "http://"+global.ServerHost+":"+global.ServerPort+"/"+url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}
	return body, nil
}

type QueryReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
	UUID      string `json:"UUID" binding:"required"`
}

type QueryReq2 struct {
	UUID string `json:"UUID" binding:"required"`
}
type ReturnAccountState struct {
	AccountAddr string `json:"account"`
	Balance     string `json:"balance"`
}
type TxReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	To        string `json:"To" binding:"required"`
	Value     string `json:"Value" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
	Fee       string `json:"Fee" `
}

var config DynamicConfig

func GetPublicKeyFromPrivateKey(p string) string {
	privateKey := new(big.Int)
	privateKey.SetString(p, 10)
	x, y := elliptic.P256().ScalarBaseMult(privateKey.Bytes())
	pubKeyBytes := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	return hex.EncodeToString(pubKeyBytes)
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
func GetAddress() string {
	decodeString, _ := hex.DecodeString(global.PublicKey)
	hash := sha256.Sum256(decodeString)
	hash2 := hash[:20]
	address := hex.EncodeToString(hash2)
	return address
}
func printbanner() {
	fmt.Println(" ______                  __                       ______  __               _\n|_   _ \\                [  |  _                 .' ___  |[  |             (_)           \n  | |_) | _ .--.   .--.  | | / ] .---.  _ .--. / .'   \\_| | |--.   ,--.   __   _ .--.   \n  |  __'.[ `/'`\\]/ .'`\\ \\| '' < / /__\\\\[ `/'`\\]| |        | .-. | `'_\\ : [  | [ `.-. |  \n _| |__) || |    | \\__. || |`\\ \\| \\__., | |    \\ `.___.'\\ | | | | // | |, | |  | | | |  \n|_______/[___]    '.__.'[__|  \\_]'.__.'[___]    `.____ .'[___]|__]\\'-;__/[___][___||__]  (academic)")
}
func printDisclaimers() {
	fmt.Println("\nBrokerChain仅供学术交流使用，用户不得使用BrokerChain从事任何非法活动。\n用户使用BrokerChain所产生的任何直接或间接后果，均与BrokerChain创始团队无关。\nBrokerChain创始团队保留随时修改、更新或终止BrokerChain的权利，且无需事先通知用户。\n用户在使用BrokerChain时，应自行承担风险，并同意放弃对创始团队的任何索赔权利。\n本免责声明受中华人民共和国法律管辖，并按照其解释。\n")
}
func getversion() {
	version, err1 := Get("getversion", []byte{})
	if err1 != nil {
		return
	}
	if len(string(version)) == 5 && string(version[0]) == "1" && global.Version != string(version) {
		fmt.Println()
		fmt.Println("=========================================")
		fmt.Println("Client version too old! Please visit https://github.com/HuangLab-SYSU/brokerchain-academic and update your client to the newest version.")
		fmt.Println("=========================================")
		fmt.Println()
		time.Sleep(10 * time.Second)
		os.Exit(1)
		return
	}
}

func handlequeryacc(reader *bufio.Reader) {
	fmt.Println("Please enter the address to query:")
	address, _ := reader.ReadString('\n')
	address = strings.TrimSpace(address)
	qreq := QueryReq2{
		UUID: address,
	}
	m, _ := json.Marshal(qreq)
	data1, err := Post("query-g2", m)
	if err != nil {
		fmt.Println(err)
		return
	}

	var r ReturnAccountState
	err = json.Unmarshal(data1, &r)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println()
	Unit := new(big.Float)
	Unit.SetString(global.Uint)
	bf := new(big.Float)
	bf.SetString(r.Balance)
	bf1 := new(big.Float)
	bf1.Quo(bf, Unit)
	fmt.Println("Your account address is:", r.AccountAddr, ",the balance of your account is:", bf1.Text('f', -1))
	return
}

func handletransfer(reader *bufio.Reader) {
	fmt.Println("Please enter the filename for the private key:")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 读取文件内容
	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 将字节切片转换为字符串并打印
	content := string(data)
	global.PrivateKey = content
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 10)
	global.PublicKey = GetPublicKeyFromPrivateKey(global.PrivateKey)

	file.Close()

	rands := uuid.New().String()
	thedata := rands + GetAddress()
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

	qreq := QueryReq{
		PublicKey: global.PublicKey,
		RandomStr: rands,
		Sign1:     sign1,
		Sign2:     sign2,
		UUID:      GetAddress(),
	}
	m, _ := json.Marshal(qreq)
	data1, err := Post("query-g", m)
	if err != nil {
		fmt.Println(err)
		return
	}

	var r ReturnAccountState
	err = json.Unmarshal(data1, &r)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println()
	Unit := new(big.Float)
	Unit.SetString(global.Uint)
	bf := new(big.Float)
	bf.SetString(r.Balance)
	bf1 := new(big.Float)
	bf1.Quo(bf, Unit)
	fmt.Println("Your account address is:", r.AccountAddr, ",the balance of your account is:", bf1.Text('f', -1))

	fmt.Println("Please enter the address of recipient's account:")
	to, _ := reader.ReadString('\n')
	to = strings.TrimSpace(to)

	for r.AccountAddr == to {
		fmt.Println("The recipient's account address cannot be the same as the payer's. Please re-enter the recipient's account address:")
		to, _ = reader.ReadString('\n')
		to = strings.TrimSpace(to)
	}

	fmt.Println("Please enter the amount to transfer:")
	val, _ := reader.ReadString('\n')
	val = strings.TrimSpace(val)

	fmt.Println("Please enter the fee:")
	fee, _ := reader.ReadString('\n')
	fee = strings.TrimSpace(fee)

	randstr := uuid.New().String()
	thedata1 := randstr + to + val + fee
	sign21, sign22, _ := SignECDSA(global.PrivateKeyBigInt, thedata1)

	qreq1 := TxReq{
		PublicKey: global.PublicKey,
		RandomStr: randstr,
		Sign1:     sign21,
		Sign2:     sign22,
		To:        to,
		Value:     val,
		Fee:       fee,
	}
	m1, _ := json.Marshal(qreq1)
	data2, err := Post("sendtx", m1)
	if err != nil {
		fmt.Println(err)
		return
	}
	if strings.Contains(string(data2), "success") {
		fmt.Println("Transfer successful.")
	} else {
		fmt.Println("Transfer failed.")
	}

	return
}

func handleclaim(reader *bufio.Reader) {
	fmt.Println("Please enter the filename for the private key:")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 将字节切片转换为字符串并打印
	content := string(data)
	global.PrivateKey = content
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 10)
	global.PublicKey = GetPublicKeyFromPrivateKey(global.PrivateKey)
	file.Close()

	randstr := uuid.New().String()
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, randstr)
	claimreq := ClaimReq{
		PublicKey: global.PublicKey,
		RandomStr: randstr,
		Sign1:     sign1,
		Sign2:     sign2,
	}
	marshal, _ := json.Marshal(claimreq)
	data1, err := Post("claim", marshal)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result: " + string(data1))
}

type ClaimReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}

func handleopenwallet(reader *bufio.Reader) {
	fmt.Println("Please enter the filename for the private key:")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 读取文件内容
	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 将字节切片转换为字符串并打印
	content := string(data)
	global.PrivateKey = content
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 10)
	global.PublicKey = GetPublicKeyFromPrivateKey(global.PrivateKey)

	file.Close()

	gin.DisableConsoleColor()
	f, _ := os.Create("gin.log")
	gin.DefaultWriter = io.MultiWriter(f)
	//gin.DefaultWriter = io.Discard
	//gin.DefaultErrorWriter = io.Discard
	r := gin.Default()
	r.Use(CorsConfig())
	// 加载 HTML 模板
	r.LoadHTMLGlob("html/*")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.POST("/", func(c *gin.Context) {
		bytes1, e := ioutil.ReadAll(c.Request.Body)
		if e != nil {
			c.JSON(http.StatusBadRequest, RpcResponse{
				Jsonrpc: "2.0",
				Id:      0,
				Error:   map[string]interface{}{"code": -32700, "message": "Parse error"},
			})
			return
		}
		fmt.Println(string(bytes1))

		flag1 := true
		flag2 := true
		var request1 []RpcRequest
		var request2 RpcRequest
		e1 := json.Unmarshal(bytes1, &request1)
		if e1 != nil {
			flag1 = false
		}
		e2 := json.Unmarshal(bytes1, &request2)
		if e2 != nil {
			flag2 = false
		}

		if !flag1 && !flag2 {
			c.JSON(http.StatusBadRequest, RpcResponse{
				Jsonrpc: "2.0",
				Id:      0,
				Error:   map[string]interface{}{"code": -32700, "message": "Parse error"},
			})
			return
		}

		if flag1 {
			responselist := []RpcResponse{}
			for _, request := range request1 {
				response := RpcResponse{
					Jsonrpc: "2.0",
					Id:      request.Id,
				}
				switch request.Method {
				case "eth_getBlockByNumber":
					response.Result = eth_getBlockByNumber(request)
				case "eth_chainId":
					response.Result = eth_chainId(request)
				case "net_version":
					response.Result = net_version(request)
				case "eth_accounts":
					response.Result = eth_accounts(request)
				case "eth_getBalance":
					response.Result = eth_getBalance(request)
				case "eth_estimateGas":
					response.Result = eth_estimateGas(request)
				case "eth_blockNumber":
					response.Result = eth_blockNumber(request)
				case "eth_getTransactionReceipt":
					response.Result = eth_getTransactionReceipt(request)
				case "eth_getCode":
					response.Result = eth_getCode(request)
				case "eth_getTransactionByHash":
					response.Result = eth_getTransactionByHash(request)
				case "eth_gasPrice":
					response.Result = eth_gasPrice(request)
				case "eth_maxPriorityFeePerGas":
					response.Result = eth_maxPriorityFeePerGas(request)
				case "eth_call":
					response.Result = eth_call(request)

				case "eth_sendTransaction":
					aaa, e3 := eth_sendTransaction(request)
					if e3 != nil {
						response.Error = aaa
					} else {
						response.Result = aaa
					}

					//gasPrice:=""
					//if obj["gasPrice"] != nil {
					//	gasPrice=obj["gasPrice"].(string)
					//}
					//s := value[2:]
					//if len(s)%2 != 0 {
					//	s = "0" + s
					//}
					//byteSlice, _ := hex.DecodeString(s)
					//var bigInt big.Int
					//bigInt.SetBytes(byteSlice)
					//inp, _ := hex.DecodeString(input1[2:])
				}
				responselist = append(responselist, response)
			}
			c.JSON(http.StatusOK, responselist)
			return
		}
		if flag2 {
			response := RpcResponse{
				Jsonrpc: "2.0",
				Id:      request2.Id,
			}
			switch request2.Method {
			case "eth_gasPrice":
				response.Result = eth_gasPrice(request2)
			case "eth_maxPriorityFeePerGas":
				response.Result = eth_maxPriorityFeePerGas(request2)
			case "eth_getBlockByNumber":
				response.Result = eth_getBlockByNumber(request2)
			case "eth_chainId":
				response.Result = eth_chainId(request2)
			case "net_version":
				response.Result = net_version(request2)
			case "eth_accounts":
				response.Result = eth_accounts(request2)
			case "eth_getBalance":
				response.Result = eth_getBalance(request2)
			case "eth_estimateGas":
				response.Result = eth_estimateGas(request2)
			case "eth_getCode":
				response.Result = eth_getCode(request2)
			case "eth_blockNumber":
				response.Result = eth_blockNumber(request2)
			case "eth_getTransactionReceipt":
				response.Result = eth_getTransactionReceipt(request2)
			case "eth_getTransactionByHash":
				response.Result = eth_getTransactionByHash(request2)
			case "eth_call":
				response.Result = eth_call(request2)
			case "eth_sendTransaction":
				aaa, e3 := eth_sendTransaction(request2)
				if e3 != nil {
					response.Error = aaa
				} else {
					response.Result = aaa
				}
			}
			c.JSON(http.StatusOK, response)
			return
		}

	})

	r.GET("/api/balance", func(c *gin.Context) {
		rands := uuid.New().String()
		thedata := rands + GetAddress()
		sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

		qreq := QueryReq{
			PublicKey: global.PublicKey,
			RandomStr: rands,
			Sign1:     sign1,
			Sign2:     sign2,
			UUID:      GetAddress(),
		}
		m, _ := json.Marshal(qreq)
		data1, err := Post("query-g", m)
		if err != nil {
			fmt.Println(err)
			return
		}

		var r ReturnAccountState
		err = json.Unmarshal(data1, &r)
		if err != nil {
			fmt.Println(err)
			return
		}
		Unit := new(big.Float)
		Unit.SetString(global.Uint)
		bf := new(big.Float)
		bf.SetString(r.Balance)
		bf1 := new(big.Float)
		bf1.Quo(bf, Unit)

		fmt.Println()
		//fmt.Println("账户地址是:", r.AccountAddr, ",余额是:"+bf1.Text('f', -1))
		c.JSON(http.StatusOK, gin.H{"balance": bf1.Text('f', -1), "addr": r.AccountAddr})
	})

	// 定义转账的 API 端点
	r.POST("/api/transfer", func(c *gin.Context) {
		var request struct {
			RecipientAddress string `json:"recipientAddress"`
			Amount           string `json:"amount"`
			Fee              string `json:"fee"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		if request.RecipientAddress == "" || request.Amount == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		rands := uuid.New().String()
		thedata := rands + GetAddress()
		sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

		qreq := QueryReq{
			PublicKey: global.PublicKey,
			RandomStr: rands,
			Sign1:     sign1,
			Sign2:     sign2,
			UUID:      GetAddress(),
		}
		to := request.RecipientAddress
		m, _ := json.Marshal(qreq)
		data1, err := Post("query-g", m)
		if err != nil {
			fmt.Println(err)
			return
		}

		var r ReturnAccountState
		err = json.Unmarshal(data1, &r)
		if err != nil {
			fmt.Println(err)
			return
		}

		if r.AccountAddr == to {
			fmt.Println("收款账户地址不得和付款账户地址相同，请重新输入要收款账户的地址:")
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transfer failed. 收款账户地址不得和付款账户地址相同"})
			return
		}

		randstr := uuid.New().String()
		thedata1 := ""
		if request.Fee == "" {
			thedata1 = randstr + to + request.Amount
		} else {
			thedata1 = randstr + to + request.Amount + request.Fee
		}

		sign21, sign22, _ := SignECDSA(global.PrivateKeyBigInt, thedata1)

		qreq1 := TxReq{
			PublicKey: global.PublicKey,
			RandomStr: randstr,
			Sign1:     sign21,
			Sign2:     sign22,
			To:        to,
			Value:     request.Amount,
		}
		if request.Fee != "" {
			qreq1.Fee = request.Fee
		}

		m1, _ := json.Marshal(qreq1)
		data2, err := Post("sendtx", m1)
		if err != nil {
			fmt.Println(err)
			return
		}
		if strings.Contains(string(data2), "success") {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transfer successful"})
		} else {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transfer failed. " + string(data2)})
		}

	})
	freePort, _ := getFreePort()
	fmt.Println()
	fmt.Println("-----********************************************-----")
	fmt.Println("Your account address is:【" + GetAddress() + "】")
	fmt.Println("The browser wallet URL is:" + "【http://127.0.0.1:" + strconv.Itoa(freePort) + "】")
	fmt.Println("-----********************************************-----")
	fmt.Println()
	go r.Run("0.0.0.0:" + strconv.Itoa(freePort))

	file2, err := os.OpenFile("The browser wallet URL of account "+GetAddress()+".txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = file2.Write([]byte("http://127.0.0.1:" + strconv.Itoa(freePort)))
	if err != nil {
		fmt.Println(err)
		return
	}
	file2.Sync()
	file2.Close()

	if runtime.GOOS == "windows" {
		url := "http://127.0.0.1:" + strconv.Itoa(freePort)
		cmd := "cmd"
		args := []string{"/c", "start"}
		args = append(args, url)
		exec.Command(cmd, args...).Start()
	}
	for {
		time.Sleep(1 * time.Second)
	}
	return
}
func handlegeneratekey(reader *bufio.Reader) bool {
	fmt.Println("Please enter the filename to save the generated private key:")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	_, err2 := os.Stat(filename)
	if !os.IsNotExist(err2) {
		fmt.Println("The file is already exists. Please enter a different filename.")
		time.Sleep(3 * time.Second)
		return false
	}

	PrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand2.Reader)
	if err != nil {
		fmt.Println("Failed to generate public/private keys:", err)
		return false
	}
	//fmt.Printf("Public key generated: %s\n", publicKey)
	if len(PrivateKey.D.String()) >= 74 {
		fmt.Println("Private key generated: ", PrivateKey.D.String()[:4]+"***********************"+PrivateKey.D.String()[74:])
	}
	global.PrivateKey = PrivateKey.D.String()
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 10)
	global.PublicKey = GetPublicKeyFromPrivateKey(global.PrivateKey)

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		time.Sleep(3 * time.Second)
		return false
	}

	content := PrivateKey.D.String()
	_, err = file.Write([]byte(content))
	if err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Println("The private key is successfully saved to file:" + filename)
	file.Close()
	return true
}
func handleexistprivatekey(reader *bufio.Reader) bool {
	fmt.Println("Please enter the filename for the private key:")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}

	// 读取文件内容
	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		time.Sleep(3 * time.Second)
		return false
	}

	// 将字节切片转换为字符串并打印
	content := string(data)
	global.PrivateKey = content
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 10)
	global.PublicKey = GetPublicKeyFromPrivateKey(global.PrivateKey)

	file.Close()
	return true
}

func tryjoin() bool {
	count := 0
	for {
		count += 1
		if count > 10 {
			fmt.Println("join failed, try again later")
			return false
		}
		problem := ""
		answer := ""
		difficulity := ""
		var err error
		for {
			problem, difficulity, err = GetProblem()
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println("Start solving problem:" + problem + ",difficulty:" + difficulity)
			answer = SolveProblem(problem, difficulity)
			if answer != "" {
				fmt.Println("Have solved problem " + problem + ",difficulty:" + difficulity + ", answer is " + answer)
				break
			}
			fmt.Println("Solve problem failed, will require new problem")
		}
		if Join(answer) {
			fmt.Println("Join successfully, waiting for construct a new shard...")
			return true
		}
	}
}

func main() {
	printbanner()
	printDisclaimers()
	getversion()
	go func() {
		for {
			time.Sleep(10 * time.Second)
			getversion()
		}
	}()
	params.ReadConfigFile()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("Welcome. Please enter an option:")
		fmt.Println("1: Join BrokerChain as a consensus node && Open the wallet.")
		fmt.Println("2: Open the wallet.")
		fmt.Println("3: Query an account and its balance if given an address.")
		fmt.Println("4: Transfer tokens to another account.")
		fmt.Println("5: Claim BKC academic tokens through faucets.")
		input0, _ := reader.ReadString('\n')
		input0 = strings.TrimSpace(input0)
		if input0 == "3" {
			handlequeryacc(reader)
			fmt.Println()
			continue
		}
		if input0 == "4" {
			handletransfer(reader)
			fmt.Println()
			continue
		}
		if input0 == "2" {
			handleopenwallet(reader)
			fmt.Println()
			continue
		}

		if input0 == "5" {
			handleclaim(reader)
			fmt.Println()
			continue
		}

		if input0 != "1" {
			fmt.Println("Invalid input.")
			fmt.Println()
			continue
		}
		break
	}

	for {
		fmt.Println("Please enter an option:")
		fmt.Println("1: Generate a pair of (public/private) keys for a new account")
		fmt.Println("2: Use the private key of an existing account")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		var _ error
		flag := false
		switch input {
		case "1":
			if !handlegeneratekey(reader) {
				break
			}else {
				flag = true
				break
			}
		case "2":
			if !handleexistprivatekey(reader) {
				break
			}else {
				flag = true
				break
			}
		default:
			fmt.Println("Invalid input.")
			fmt.Println()
			continue
		}
		if flag {
			break
		}
	}
	Runhttp()
	for {
		if !JoinPoS() {
			fmt.Println("Join failed. ")
			return
		}
		WaitConstructShard()
		build_()
		connect()
		build.BuildNewPbftNode(uint64(nodeID), uint64(nodeNum), uint64(shardID), uint64(shardNum))
		time.Sleep(1 * time.Second)
	}

}
func build_() {
	maxShardId, _ := strconv.Atoi(config.NewNodeinfos[len(config.NewNodeinfos)-1].ShardID)
	shardNum = maxShardId + 1
	nodeNum = len(config.NewNodeinfos)
	shardID = maxShardId
	for i, node := range config.NewNodeinfos {
		if node.PublicKey == GetAddress() {
			nodeID = i
			break
		}
	}
	params.ShardNum = shardNum
	params.NodesInShard = nodeNum

	nodes := make([]NodeInfo, 0)
	if config.OldNodeinfos != nil {
		nodes = append(nodes, config.OldNodeinfos...)
	}
	nodes = append(nodes, config.NewNodeinfos...)
	shardid := 0
	nodeid := -1
	for _, node := range nodes {
		nodeid++
		shardidnow, _ := strconv.Atoi(node.ShardID)
		if shardidnow != shardid {
			shardid = shardidnow
			nodeid = 0
		}
		if params.IPmap_nodeTable[uint64(shardid)] == nil {
			params.IPmap_nodeTable[uint64(shardid)] = make(map[uint64]string)
		}
		params.IPmap_nodeTable[uint64(shardid)][uint64(nodeid)] = node.Ip + ":" + node.Port
	}
	//fmt.Println("has generated ipmap:")
	for i := 0; i < shardNum; i++ {
		for j := 0; j < nodeNum; j++ {
			if params.IPmap_nodeTable[uint64(i)] == nil {
				params.IPmap_nodeTable[uint64(i)] = make(map[uint64]string)
			}
			params.IPmap_nodeTable[uint64(i)][uint64(j)] = strconv.Itoa(i) + ":" + strconv.Itoa(j)
			//fmt.Println("S" + strconv.Itoa(i) + "N" + strconv.Itoa(j) + ":" + params.IPmap_nodeTable[uint64(i)][uint64(j)])
		}
	}

	params.SupervisorAddr = global.ServerHost + ":" + strconv.Itoa(38800)
	params.IPmap_nodeTable[params.SupervisorShard] = make(map[uint64]string)
	params.IPmap_nodeTable[params.SupervisorShard][0] = params.SupervisorAddr
}

func connect() {
	for i := 0; i < 10; i++ {
		randstr := uuid.New().String()
		sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, randstr)
		getproblemreq := ConReq{
			PublicKey: global.PublicKey,
			RandomStr: randstr,
			Sign1:     sign1,
			Sign2:     sign2,
		}
		marshal, _ := json.Marshal(getproblemreq)
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err2 := dialer.Dial("tcp", global.ServerHost+":"+global.ServerForwardPort)
		if err2 != nil {
			log.Println("Connect error", err2)
		} else {
			conn.(*net.TCPConn).SetKeepAlive(true)
			global.Conn = conn
			networks.TcpDial(marshal, "auth")
			break
		}
	}
}

func GetRandStrSign() (string, string, string) {
	uid := uuid.New().String()
	r, s, _ := SignECDSA(global.PrivateKeyBigInt, uid)
	return uid, r, s
}

func getFreePort() (int, error) {
	rand.Seed(time.Now().UnixNano())
	for {
		p := 20000 + rand.Intn(40001)

		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			return 0, err
		}

		listener, err := net.ListenTCP("tcp", addr)
		if err == nil {
			listener.Close()
			return p, nil
		}
	}
}

type JoinReq2 struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}

func JoinPoS() bool {
	randstr := uuid.New().String()
	thedata := randstr
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	joinreq := JoinReq2{
		PublicKey: global.PublicKey,
		RandomStr: randstr,
		Sign1:     sign1,
		Sign2:     sign2,
	}
	m, _ := json.Marshal(joinreq)
	data, err := Post("join2", m)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if strings.Contains(string(data), "success") {
		return true
	} else {
		fmt.Println(string(data))
		if strings.Contains(string(data), "do not join system using the same private key") {
			fmt.Println()
			fmt.Println("=============********************************************************************************=============")
			fmt.Println("【Join failed】. Please do not join system using the same private key. Program will exit after 10 seconds.")
			fmt.Println("=============********************************************************************************=============")
			fmt.Println()
			time.Sleep(10 * time.Second)
			os.Exit(1)
		}
		if strings.Contains(string(data), "Your balance is less than") {
			fmt.Println()
			fmt.Println("=============********************************************************************************=============")
			fmt.Println("【PoS failed】. Your account balance is not enough to join BrokerChain. Program will exit after 10 seconds.")
			fmt.Println("=============********************************************************************************=============")
			fmt.Println()
			time.Sleep(10 * time.Second)
			os.Exit(1)
		}
	}
	return false

}

func Join(answer string) bool {
	randstr := uuid.New().String()
	p, err := getFreePort()
	if err != nil {
		fmt.Println("no port is available:" + err.Error())
		return false
	}
	Ip := "127.0.0.1"
	thedata := randstr
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	joinreq := JoinReq{
		PublicKey: global.PublicKey,
		RandomStr: randstr,
		Sign1:     sign1,
		Sign2:     sign2,
		Answer:    answer,
		Ip:        Ip,
		Port:      strconv.Itoa(p),
	}
	m, _ := json.Marshal(joinreq)
	data, err := Post("join", m)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if strings.Contains(string(data), "success") {
		return true
	} else {
		fmt.Println(string(data))
		if strings.Contains(string(data), "do not join system using the same private key") {
			fmt.Println("Please do not join system using the same private key! Program will exit after 10 seconds.")
			time.Sleep(10 * time.Second)
			os.Exit(1)
		}
	}
	return false

}

func GetProblem() (string, string, error) {
	randstr := uuid.New().String()
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, randstr)
	getproblemreq := GetProblemReq{
		PublicKey: global.PublicKey,
		RandomStr: randstr,
		Sign1:     sign1,
		Sign2:     sign2,
	}
	marshal, _ := json.Marshal(getproblemreq)
	data, err := Post("getProblem", marshal)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	res := GetProblemRes{}
	if err = json.Unmarshal(data, &res); err != nil {
		return "", "", err
	}
	if res.Message != "create problem success" {
		return "", "", errors.New("create problem failed")
	}
	return res.Data.UUID, res.Data.Difficulty, nil
}

func SolveProblem(problem string, difficulty string) string {
	diff, _ := strconv.Atoi(difficulty)
	answer := ""

	resultChan := make(chan int, 1)
	doneChan := make(chan bool, 1)
	var wg sync.WaitGroup
	maxRange := 1000000000

	workers := runtime.NumCPU()

	if workers > 16 {
		workers = 16
	}
	wg.Add(workers)
	perWorker := maxRange / workers
	flag := atomic.Bool{}
	for i := 0; i < workers; i++ {
		start := i * perWorker
		end := (i + 1) * perWorker
		if i == workers-1 {
			end = maxRange // 最后一个处理剩余部分
		}
		go worker(&wg, start, end, problem, diff, resultChan, &flag)

	}

	go func() {
		wg.Wait()
		doneChan <- true
		flag.Store(true)
	}()
	select {
	case i := <-resultChan:
		flag.Store(true)
		answer = strconv.Itoa(i)
		break
	case <-doneChan:
		fmt.Printf("No solution found in range %d\n", maxRange)
	}

	return answer
}

func worker(wg *sync.WaitGroup, start, end int, problem string, difficulty int, resultChan chan<- int, flag *atomic.Bool) {
	defer wg.Done()
	s1 := GetAddress() + problem
	previ := start
	for i := start; i < end; i++ {
		if i-previ > 100 {
			previ = i
			if flag.Load() {
				return
			}
		}
		sum256 := sha256.Sum256([]byte(s1 + strconv.Itoa(i)))
		if check(sum256, difficulty) {
			resultChan <- i
			return
		}
	}
}

func check(arr [32]byte, difficulty int) bool {
	count := 0
	for i := 0; i < 32 && count < difficulty; i++ {
		for j := 0; j < 8 && count < difficulty; j++ {
			if (arr[i] & (1 << (7 - j))) != 0 {
				return false
			} else {
				count++
			}
		}
	}
	return true
}

var C *websocket.Conn

func WaitConstructShard() {
	u := url.URL{Scheme: "ws", Host: global.ServerHost + ":" + global.ServerPort, Path: "/ws2"}
	//log.Printf("Connecting to %s", u.String())
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}

	C = conn

	go func() {
		_, m1, e := conn.ReadMessage()
		if e != nil {
			fmt.Println("read error:", e)
			return
		}
		if strings.Contains(string(m1), "success") {
			fmt.Println("Connect successfully, waiting construct new shard...")
		}

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				//log.Println("Read error:", err)
				return
			}
			//log.Printf("Received: %s", message)
			log.Printf("Consensus gets started...\n")
			if err = json.Unmarshal(message, &config); err != nil {
				fmt.Println("Unmarshal error:", err)
				continue
			}

			C.Close()
			return

		}
	}()

	randstr := uuid.New().String()
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, randstr)
	req := WsReq{
		PublicKey: global.PublicKey,
		RandomStr: randstr,
		Sign1:     sign1,
		Sign2:     sign2,
	}
	bytes, _ := json.Marshal(req)
	err = conn.WriteMessage(websocket.TextMessage, bytes)
	if err != nil {
		//log.Println("Write error:", err)
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-ticker.C:
			err = conn.WriteMessage(websocket.TextMessage, []byte("Hello"))
			if err != nil {
				log.Println("Write error:", err)
				return
			}

		}
	}

}

func CorsConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*") // 可将将 * 替换为指定的域名
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Header("Access-Control-Allow-Headers", "*")
		c.Header("Access-Control-Expose-Headers", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(200)
		} else {
			c.Next()
		}
	}
}

func eth_getBlockByNumber(request RpcRequest) interface{} {
	s := request.Params[0].(string)
	number := ""
	if s == "latest" {
		number = "latest"
	} else {
		number = request.Params[0].(string)[2:]
	}
	rands := uuid.New().String()
	thedata := rands + number
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

	req := GetBlockByNumReq{
		PublicKey: global.PublicKey,
		RandomStr: rands,
		Sign1:     sign1,
		Sign2:     sign2,
		UUID:      number,
	}
	m1, _ := json.Marshal(req)
	data1, err2 := Post("eth_getBlockByNumber", m1)
	if err2 != nil {
		fmt.Println(err2)
		return nil
	}
	var re RpcResponse
	json.Unmarshal(data1, &re)
	return re.Result
}

func eth_chainId(request RpcRequest) interface{} {
	return "0x1"
}

func net_version(request RpcRequest) interface{} {
	return "1"
}

func eth_accounts(request RpcRequest) interface{} {
	addr := GetAddress()
	return []string{addr}
}

func eth_getBalance(request RpcRequest) interface{} {
	UUID := request.Params[0].(string)[2:]
	//rand, sign := GetRandStrSign()
	rands := uuid.New().String()
	thedata := rands + UUID
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

	qreq := QueryReq{
		PublicKey: global.PublicKey,
		RandomStr: rands,
		Sign1:     sign1,
		Sign2:     sign2,
		UUID:      UUID,
	}
	m, _ := json.Marshal(qreq)
	data1, err := Post("query-g", m)
	if err != nil {
		fmt.Println(err)
		return "0x0"
	}

	var r ReturnAccountState
	err = json.Unmarshal(data1, &r)
	if err != nil {
		fmt.Println(err)
		return "0x0"
	}
	Unit := new(big.Float)
	Unit.SetString(global.Uint)
	bf := new(big.Float)
	bf.SetString(r.Balance)

	intVal := new(big.Int)
	bf.Int(intVal)

	hexStr := intVal.Text(16)

	return "0x" + hexStr
}

func eth_getCode(request RpcRequest) interface{} {
	UUID := request.Params[0].(string)[2:]
	rr := uuid.New().String()
	thedata := rr + UUID
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	req := GetCodeReq{
		PublicKey: global.PublicKey,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
		UUID:      UUID,
	}
	m1, _ := json.Marshal(req)
	data1, err2 := Post("eth_getCode", m1)
	if err2 != nil {
		fmt.Println(err2)
		return nil
	}
	var re RpcResponse
	json.Unmarshal(data1, &re)
	return re.Result
}

func eth_getTransactionReceipt(request RpcRequest) interface{} {
	UUID := request.Params[0].(string)[2:]
	rr := uuid.New().String()
	thedata := rr + UUID
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	req := GetTransactionReceiptReq{
		PublicKey: global.PublicKey,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
		UUID:      UUID,
	}
	m1, _ := json.Marshal(req)
	data1, err2 := Post("eth_getTransactionReceipt", m1)
	if err2 != nil {
		fmt.Println(err2)
		return nil
	}
	var re RpcResponse
	json.Unmarshal(data1, &re)
	return re.Result
}
func eth_getTransactionByHash(request RpcRequest) interface{} {
	UUID := request.Params[0].(string)[2:]
	rr := uuid.New().String()
	thedata := rr + UUID
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	req := GetTXByHashReq{
		PublicKey: global.PublicKey,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
		UUID:      UUID,
	}
	m1, _ := json.Marshal(req)
	data1, err2 := Post("eth_getTransactionByHash", m1)
	if err2 != nil {
		fmt.Println(err2)
		return nil
	}
	var re RpcResponse
	json.Unmarshal(data1, &re)
	return re.Result
}

func eth_blockNumber(request RpcRequest) interface{} {
	rr := uuid.New().String()
	thedata := rr
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

	req := GetBlockNumReq{
		PublicKey: global.PublicKey,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
	}
	m1, _ := json.Marshal(req)
	data2, err := Post("eth_blockNumber", m1)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	cc1 := RpcResponse{}
	err = json.Unmarshal(data2, &cc1)
	if err != nil {
		fmt.Println(err)
	}
	return cc1.Result
}

func eth_call(request RpcRequest) interface{} {
	obj := request.Params[0].(map[string]interface{})
	to := ""
	if obj["to"] != nil {
		to = obj["to"].(string)
	}
	value := ""
	if obj["value"] != nil {
		value = obj["value"].(string)
	}
	input1 := ""
	if obj["data"] != nil {
		input1 = obj["data"].(string)
	} else if obj["input"] != nil {
		input1 = obj["input"].(string)
	}
	rr := uuid.New().String()
	thedata := to + input1 + value + rr
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

	req := CallContractReq{
		PublicKey: global.PublicKey,
		To:        to,
		Data:      input1,
		Value:     value,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
	}

	m1, _ := json.Marshal(req)
	data2, err := Post("eth_call", m1)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	cc1 := RpcResponse{}
	err = json.Unmarshal(data2, &cc1)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data2))
	fmt.Println(cc1)

	return cc1.Result
}
func eth_sendTransaction(request RpcRequest) (interface{}, error) {
	obj := request.Params[0].(map[string]interface{})
	to := ""
	if obj["to"] != nil {
		to = obj["to"].(string)
	}
	gas := ""
	if obj["gas"] != nil {
		gas = obj["gas"].(string)
	}
	value := ""
	if obj["value"] != nil {
		value = obj["value"].(string)
	}
	input1 := ""
	if obj["data"] != nil {
		input1 = obj["data"].(string)
	} else if obj["input"] != nil {
		input1 = obj["input"].(string)
	}
	rr := uuid.New().String()
	thedata := to + input1 + value + gas + rr

	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	req := SendContractReq{
		PublicKey: global.PublicKey,
		To:        to,
		Data:      input1,
		Value:     value,
		Gas:       gas,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
	}

	m1, _ := json.Marshal(req)
	data2, err := Post("eth_sendTransaction", m1)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	cc1 := RpcResponse{}
	err = json.Unmarshal(data2, &cc1)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data2))
	fmt.Println(cc1)
	if cc1.Error != nil {
		return cc1.Error, errors.New("123")
	}

	return cc1.Result, nil
}

func eth_gasPrice(request RpcRequest) interface{} {
	return "0x3b9aca00"
}

func eth_maxPriorityFeePerGas(request RpcRequest) interface{} {
	return "0x3b9aca00"
}

func eth_estimateGas(request RpcRequest) interface{} {
	obj := request.Params[0].(map[string]interface{})
	to := ""
	if obj["to"] != nil {
		to = obj["to"].(string)
	}

	value := ""
	if obj["value"] != nil {
		value = obj["value"].(string)
	}
	input1 := ""
	if obj["data"] != nil {
		input1 = obj["data"].(string)
	} else if obj["input"] != nil {
		input1 = obj["input"].(string)
	}
	rr := uuid.New().String()
	thedata := to + input1 + value + rr
	sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)
	req := EstContractReq{
		PublicKey: global.PublicKey,
		To:        to,
		Data:      input1,
		Value:     value,
		RandomStr: rr,
		Sign1:     sign1,
		Sign2:     sign2,
	}

	m1, _ := json.Marshal(req)
	data2, err := Post("eth_estimateGas", m1)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	cc1 := RpcResponse{}
	json.Unmarshal(data2, &cc1)

	fmt.Println("eth_estimateGas:", string(data2))
	return cc1.Result
}

type NodeInfo struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	Ip        string `json:"Ip" binding:"required"`
	Port      string `json:"Port" binding:"required"`
	ShardID   string `json:"ShardID" binding:"required"`
}
type WsReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}
type DynamicConfig struct {
	OldNodeinfos []NodeInfo `json:"OldNodeinfos" binding:"required"`
	NewNodeinfos []NodeInfo `json:"NewNodeinfos" binding:"required"`
}
type RpcRequest struct {
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      interface{}   `json:"id"`
	Jsonrpc string        `json:"jsonrpc"`
}
type RpcResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Id      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type SendContractReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	To        string `json:"To" binding:"required"`
	Data      string `json:"data" binding:"required"`
	Value     string `json:"value" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Gas       string `json:"Gas" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}
type EstContractReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	To        string `json:"To" `
	Data      string `json:"data" binding:"required"`
	Value     string `json:"value" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Gas       string `json:"Gas" `
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}
type GetTransactionReceiptReq struct {
	UUID      string `json:"uuid" binding:"required"`
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}
type GetCodeReq struct {
	UUID      string `json:"uuid" binding:"required"`
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}
type TxRec struct {
	TransactionHash string `json:"transactionHash"`
	ContractAddress string `json:"contractAddress"`
	GasUsed         string `json:"gasUsed"`
	Status          string `json:"status"`
	//Logs []LogItem `json:"logs"`
}

type GetTXByHashReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
	UUID      string `json:"UUID" binding:"required"`
}
type GetBlockNumReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}
type GetBlockByNumReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
	UUID      string `json:"UUID" binding:"required"`
}
type CallContractReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	To        string `json:"To" `
	Data      string `json:"data" binding:"required"`
	Value     string `json:"value" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}

type ConReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}

type GetProblemReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
}

type GetProblemRes struct {
	Message string         `json:"message"`
	Data    GetProblemRes1 `json:"data"`
}
type GetProblemRes1 struct {
	UUID       string `json:"UUID" binding:"required"`
	Difficulty string `json:"Difficulty" binding:"required"`
}
type JoinReq struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	RandomStr string `json:"RandomStr" binding:"required"`
	Sign1     string `json:"Sign1" binding:"required"`
	Sign2     string `json:"Sign2" binding:"required"`
	Answer    string `json:"Answer" binding:"required"`
	Ip        string `json:"Ip" binding:"required"`
	Port      string `json:"Port" binding:"required"`
}

func Runhttp() {
	//gin.DisableConsoleColor()
	//gin.DefaultWriter = io.Discard
	gin.DisableConsoleColor()
	f, _ := os.Create("gin.log")
	gin.DefaultWriter = io.MultiWriter(f)
	r := gin.Default()
	r.Use(CorsConfig())
	r.LoadHTMLGlob("html/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.POST("/", func(c *gin.Context) {
		bytes1, e := ioutil.ReadAll(c.Request.Body)
		if e != nil {
			c.JSON(http.StatusBadRequest, RpcResponse{
				Jsonrpc: "2.0",
				Id:      0,
				Error:   map[string]interface{}{"code": -32700, "message": "Parse error"},
			})
			return
		}
		fmt.Println(string(bytes1))

		flag1 := true
		flag2 := true
		var request1 []RpcRequest
		var request2 RpcRequest
		e1 := json.Unmarshal(bytes1, &request1)
		if e1 != nil {
			flag1 = false
		}
		e2 := json.Unmarshal(bytes1, &request2)
		if e2 != nil {
			flag2 = false
		}

		if !flag1 && !flag2 {
			c.JSON(http.StatusBadRequest, RpcResponse{
				Jsonrpc: "2.0",
				Id:      0,
				Error:   map[string]interface{}{"code": -32700, "message": "Parse error"},
			})
			return
		}

		if flag1 {
			responselist := []RpcResponse{}
			for _, request := range request1 {
				response := RpcResponse{
					Jsonrpc: "2.0",
					Id:      request.Id,
				}
				switch request.Method {
				case "eth_getBlockByNumber":
					response.Result = eth_getBlockByNumber(request)
				case "eth_chainId":
					response.Result = eth_chainId(request)
				case "net_version":
					response.Result = net_version(request)
				case "eth_accounts":
					response.Result = eth_accounts(request)
				case "eth_getBalance":
					response.Result = eth_getBalance(request)
				case "eth_estimateGas":
					response.Result = eth_estimateGas(request)
				case "eth_blockNumber":
					response.Result = eth_blockNumber(request)
				case "eth_getTransactionReceipt":
					response.Result = eth_getTransactionReceipt(request)
				case "eth_getCode":
					response.Result = eth_getCode(request)
				case "eth_getTransactionByHash":
					response.Result = eth_getTransactionByHash(request)
				case "eth_gasPrice":
					response.Result = eth_gasPrice(request)
				case "eth_maxPriorityFeePerGas":
					response.Result = eth_maxPriorityFeePerGas(request)
				case "eth_call":
					response.Result = eth_call(request)

				case "eth_sendTransaction":
					aaa, e3 := eth_sendTransaction(request)
					if e3 != nil {
						response.Error = aaa
					} else {
						response.Result = aaa
					}

				}
				responselist = append(responselist, response)
			}
			c.JSON(http.StatusOK, responselist)
			return
		}
		if flag2 {
			response := RpcResponse{
				Jsonrpc: "2.0",
				Id:      request2.Id,
			}
			switch request2.Method {
			case "eth_gasPrice":
				response.Result = eth_gasPrice(request2)
			case "eth_maxPriorityFeePerGas":
				response.Result = eth_maxPriorityFeePerGas(request2)
			case "eth_getBlockByNumber":
				response.Result = eth_getBlockByNumber(request2)
			case "eth_chainId":
				response.Result = eth_chainId(request2)
			case "net_version":
				response.Result = net_version(request2)
			case "eth_accounts":
				response.Result = eth_accounts(request2)
			case "eth_getBalance":
				response.Result = eth_getBalance(request2)
			case "eth_estimateGas":
				response.Result = eth_estimateGas(request2)
			case "eth_getCode":
				response.Result = eth_getCode(request2)
			case "eth_blockNumber":
				response.Result = eth_blockNumber(request2)
			case "eth_getTransactionReceipt":
				response.Result = eth_getTransactionReceipt(request2)
			case "eth_getTransactionByHash":
				response.Result = eth_getTransactionByHash(request2)
			case "eth_call":
				response.Result = eth_call(request2)
			case "eth_sendTransaction":
				aaa, e3 := eth_sendTransaction(request2)
				if e3 != nil {
					response.Error = aaa
				} else {
					response.Result = aaa
				}
			}
			c.JSON(http.StatusOK, response)
			return
		}

	})

	r.GET("/api/balance", func(c *gin.Context) {
		rands := uuid.New().String()
		thedata := rands + GetAddress()
		sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

		qreq := QueryReq{
			PublicKey: global.PublicKey,
			RandomStr: rands,
			Sign1:     sign1,
			Sign2:     sign2,
			UUID:      GetAddress(),
		}
		m, _ := json.Marshal(qreq)
		data1, err := Post("query-g", m)
		if err != nil {
			fmt.Println(err)
			return
		}

		var r ReturnAccountState
		err = json.Unmarshal(data1, &r)
		if err != nil {
			fmt.Println(err)
			return
		}
		Unit := new(big.Float)
		Unit.SetString(global.Uint)
		bf := new(big.Float)
		bf.SetString(r.Balance)
		bf1 := new(big.Float)
		bf1.Quo(bf, Unit)

		c.JSON(http.StatusOK, gin.H{"balance": bf1.Text('f', -1), "addr": r.AccountAddr})
	})

	// 定义转账的 API 端点
	r.POST("/api/transfer", func(c *gin.Context) {
		var request struct {
			RecipientAddress string `json:"recipientAddress"`
			Amount           string `json:"amount"`
			Fee              string `json:"fee"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
			return
		}

		rands := uuid.New().String()
		thedata := rands + GetAddress()
		sign1, sign2, _ := SignECDSA(global.PrivateKeyBigInt, thedata)

		qreq := QueryReq{
			PublicKey: global.PublicKey,
			RandomStr: rands,
			Sign1:     sign1,
			Sign2:     sign2,
			UUID:      GetAddress(),
		}
		to := request.RecipientAddress
		m, _ := json.Marshal(qreq)
		data1, err := Post("query-g", m)
		if err != nil {
			fmt.Println(err)
			return
		}

		var r ReturnAccountState
		err = json.Unmarshal(data1, &r)
		if err != nil {
			fmt.Println(err)
			return
		}

		if r.AccountAddr == to {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transfer failed. 收款账户地址不得和付款账户地址相同"})
			return
		}

		randstr := uuid.New().String()

		thedata1 := ""
		if request.Fee == "" {
			thedata1 = randstr + to + request.Amount
		} else {
			thedata1 = randstr + to + request.Amount + request.Fee
		}

		sign21, sign22, _ := SignECDSA(global.PrivateKeyBigInt, thedata1)

		qreq1 := TxReq{
			PublicKey: global.PublicKey,
			RandomStr: randstr,
			Sign1:     sign21,
			Sign2:     sign22,
			To:        to,
			Value:     request.Amount,
		}
		if request.Fee != "" {
			qreq1.Fee = request.Fee
		}
		m1, _ := json.Marshal(qreq1)
		data2, err := Post("sendtx", m1)
		if err != nil {
			fmt.Println(err)
			return
		}
		if strings.Contains(string(data2), "success") {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transfer successful"})
		} else {
			c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transfer failed. " + string(data2)})
		}

	})
	freePort, _ := getFreePort()
	fmt.Println()
	fmt.Println("-----********************************************-----")
	fmt.Println("Your account address is:【" + GetAddress() + "】")
	fmt.Println("The browser wallet URL is:" + "【http://127.0.0.1:" + strconv.Itoa(freePort) + "】")
	fmt.Println("-----********************************************-----")
	fmt.Println()
	go r.Run("0.0.0.0:" + strconv.Itoa(freePort))
	file, err := os.OpenFile("The browser wallet URL of account "+GetAddress()+".txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = file.Write([]byte("http://127.0.0.1:" + strconv.Itoa(freePort)))
	if err != nil {
		fmt.Println(err)
		return
	}
	file.Sync()
	file.Close()
	time.Sleep(100 * time.Millisecond)
	if runtime.GOOS == "windows" {
		url := "http://127.0.0.1:" + strconv.Itoa(freePort)
		cmd := "cmd"
		args := []string{"/c", "start"}
		args = append(args, url)
		exec.Command(cmd, args...).Start()
	}
}
