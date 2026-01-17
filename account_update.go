package main

import (
	"blockEmulator/global"
	"bufio"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

var redString = "\033[31m%v\033[0m"

func updateAccount(reader *bufio.Reader) {
	fmt.Println("Please enter the private key file path (relative path):")
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
	fmt.Printf("old address: "+redString+"\n", address)
	fmt.Printf("address balance: "+redString+"(BKC)"+"\n", balance)

	if balance == "0" {
		fmt.Println("The old account balance of the account is 0.")
		return
	}

	fmt.Println("Do you need to generate a new version of the account compatible with the Ethereum ecosystem (y/n):")
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
		fmt.Printf("New private key: "+redString+"\n", newPrivateKey)
		fmt.Printf("New address: "+redString+"\n", newAddress)

		fmt.Println("Do you need to transfer the balance from your old account to the new account (y/n)?")
		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		req := TransferToNewReq{
			From:   address,
			To:     newAddress,
			PrivK:  privateKey,
			Amount: balance,
		}
		log.Printf("updateAccount req: %+v", req)
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

func updateAccountAuto(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	err = file.Close()
	if err != nil {
		return err
	}
	privateKeyOld := string(data)
	publicKeyOld := getPublicKeyFromPrivateKeyOld(privateKeyOld)
	addressOld := getAddressFromPublicKeyOld(publicKeyOld)
	balance := getAccountBalance(addressOld)

	ts := time.Now().Unix()
	tsStr := strconv.FormatInt(ts, 10)
	oldFilename := filename + "_old_" + tsStr
	_, err = os.Stat(oldFilename)
	if !os.IsNotExist(err) {
		fmt.Printf("The file [%v] is already exists. Please enter a different filename.\n", oldFilename)
		return err
	}
	err = os.WriteFile(oldFilename, []byte(privateKeyOld), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("旧账户地址: "+redString+"\n", addressOld)
	fmt.Printf("账户当前余额: "+redString+"(BKC)"+"\n", balance)

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("Failed to generate public/private keys:", err)
		return err
	}

	global.PrivateKey = hex.EncodeToString(privateKey.D.Bytes())
	global.PrivateKeyBigInt.SetString(global.PrivateKey, 16)
	global.PublicKey, err = GetPublicKeyFromPrivateKey(global.PrivateKey)
	if err != nil {
		return err
	}
	newPrivateKeyStr := hex.EncodeToString(global.PrivateKeyBigInt.Bytes())

	newAddress := GetAddress()

	fmt.Printf("新私钥: "+redString+"\n", newPrivateKeyStr)
	fmt.Printf("新账户地址: "+redString+"\n", newAddress)

	if balance == "0" {
		fmt.Println("The old account balance of the account is 0.")
		err = os.WriteFile(filename, []byte(newPrivateKeyStr), 0644)
		if err != nil {
			fmt.Printf("Key update successful, but saving the new private key failed. Please save it manually. %v \n", newPrivateKeyStr)
			return err
		}
		return nil
	}

	req := TransferToNewReq{
		From:   addressOld,
		To:     newAddress,
		PrivK:  privateKeyOld,
		Amount: balance,
	}
	m, err := json.Marshal(req)
	if err != nil {
		fmt.Println("Failed to marshal request:", err)
		return err
	}

	respond, err := Post("transferToNewAccount", m)
	if err != nil {
		fmt.Println("Failed to post request:", err)
		return err
	}
	res := string(respond)
	fmt.Println(res)
	if strings.Contains(res, "error") {
		return errors.New("fail to update account, try again")
	} else {
		err = os.WriteFile(filename, []byte(newPrivateKeyStr), 0644)
		if err != nil {
			fmt.Printf("Key update successful, but saving the new private key failed. Please save it manually. %v \n", newPrivateKeyStr)
			return err
		}
	}
	return nil
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
	global.PublicKey, err = GetPublicKeyFromPrivateKey(global.PrivateKey)
	if err != nil {
		return false, ""
	}
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
