package main

import (
	"blockEmulator/global"
	"bufio"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

var redString = "\033[31m%v\033[0m"

func updateAccount(reader *bufio.Reader) {
	fmt.Println("请输入私钥文件路径(相对路径):")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}
	privateKey := string(data)
	publicKey := getPublicKeyFromPrivateKeyOld(privateKey)
	address := getAddressFromPublicKeyOld(publicKey)
	balance := getAccountBalance(address)
	fmt.Printf("旧账户地址: "+redString+"\n", address)
	fmt.Printf("账户当前余额: "+redString+"(BKC)"+"\n", balance)
	fmt.Println("是否需要生成新版的账户(y/n):")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	var newPrivateKey string
	var newAddress string
	var isSuccessd bool
	if choice == "y" {
		isSuccessd, newPrivateKey = handleGenerateKeyForUpdate(reader)
	} else {
		return
	}
	if isSuccessd {
		newAddress = GetAddress()
		fmt.Printf("新私钥: "+redString+"\n", newPrivateKey)
		fmt.Printf("新账户地址: "+redString+"\n", newAddress)

		fmt.Println("是否需要将旧账户的余额转移到新账户(y/n):")
		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		req := TransferToNewReq{
			From:   address,
			To:     newAddress,
			PrivK:  privateKey,
			Amount: balance,
		}
		m, _ := json.Marshal(req)
		if choice == "y" {
			fmt.Printf("From: "+redString+", Balance: "+redString+"(BKC)"+"\n", address, getAccountBalance(address))
			fmt.Printf("To:"+redString+"\n", newAddress)
			respond, _ := Post("transferToNewAccount", m)
			fmt.Printf("respond: %v", string(respond))
		} else {
			return
		}
	}
}

type TransferToNewReq struct {
	From   string `json:"from"`
	To     string `json:"to"`
	PrivK  string `json:"privK"`
	Amount string `json:"amount"`
}

func handleGenerateKeyForUpdate(reader *bufio.Reader) (bool, string) {
	fmt.Println("Please enter the filename to save the generated private key:")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	_, err2 := os.Stat(filename)
	if !os.IsNotExist(err2) {
		fmt.Println("The file is already exists. Please enter a different filename.")
		time.Sleep(3 * time.Second)
		return false, ""
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("Failed to generate public/private keys:", err)
		return false, ""
	}
	global.PrivateKey = hex.EncodeToString(privateKey.D.Bytes())
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 16)
	global.PublicKey = GetPublicKeyFromPrivateKey(global.PrivateKey)

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		time.Sleep(3 * time.Second)
		return false, ""
	}

	content := hex.EncodeToString(global.PrivateKeyBigInt.Bytes())
	_, err = file.Write([]byte(content))
	if err != nil {
		fmt.Println(err)
		return false, ""
	}
	fmt.Println("The private key is successfully saved to file:" + filename)
	file.Close()
	return true, content
}

func getPublicKeyFromPrivateKeyOld(privKey string) string {
	privateKey := new(big.Int)
	privateKey.SetString(privKey, 10)
	x, y := elliptic.P256().ScalarBaseMult(privateKey.Bytes())
	pubKeyBytes := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	return hex.EncodeToString(pubKeyBytes)
}

func getAddressFromPublicKeyOld(publicKey string) string {
	decodeString, _ := hex.DecodeString(publicKey)
	hash := sha256.Sum256(decodeString)
	hash2 := hash[:20]
	address := hex.EncodeToString(hash2)
	return address
}

func getAccountBalance(address string) string {
	qreq := QueryReq2{
		UUID: address,
	}
	m, _ := json.Marshal(qreq)
	data1, err := Post("query-g2", m)
	if err != nil {
		fmt.Println(err)
		return "0"
	}

	var r ReturnAccountState
	err = json.Unmarshal(data1, &r)
	if err != nil {
		fmt.Println(err)
		return "0"
	}
	Unit := new(big.Float)
	Unit.SetString(global.Uint)
	bf := new(big.Float)
	bf.SetString(r.Balance)
	bf1 := new(big.Float)
	bf1.Quo(bf, Unit)
	return bf1.Text('f', -1)
}
