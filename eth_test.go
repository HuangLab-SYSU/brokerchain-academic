package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestRawTx(t *testing.T) {

	rawHex := "0xf872843b9aca00843b9aca00830334509431205f061f0cd0c0cfabb21bb8eb11649e211bb7880de0b6b3a7640000808220c3a0388fca343dff01e4e225f7729508768c07a30127aee6c50e4d71b73a7f3cd4a5a01e7cb8c11924d6b70c1751b325154e235f1d298c3ad57cc6b9b2c901cb3b9e2e" // 替换成实际 raw tx

	var tx types.Transaction
	err := tx.UnmarshalBinary(common.FromHex(rawHex))
	if err != nil {
		log.Fatal("RLP decode failed:", err)
	}

	// 输出解析内容
	fmt.Println("Tx Hash:", tx.Hash().Hex())
	fmt.Println("Nonce:", tx.Nonce())
	fmt.Println("To:", tx.To().Hex())
	fmt.Println("Value:", tx.Value())
	fmt.Println("Gas Limit:", tx.Gas())
	fmt.Println("Data:", common.Bytes2Hex(tx.Data()))
	fmt.Println("ChainID:", tx.ChainId())
	fmt.Println("Type:", tx.Type()) // 0 = Legacy, 1 = AccessList, 2 = EIP-1559

	signer := types.NewLondonSigner(tx.ChainId()) // EIP-1559
	// 旧交易用 types.NewEIP155Signer(chainID)

	from, err := types.Sender(signer, &tx)
	if err != nil {
		log.Fatal("Failed to recover sender:", err)
	}

	fmt.Println("签名者地址：", from.Hex())

	// 1. 生成私钥
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// 私钥 Hex 格式
	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Printf("Private Key: %x\n", privateKeyBytes)

	// 2. 生成公钥
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Printf("Public Key: %x\n", publicKeyBytes)

	// 3. 生成地址
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Printf("Address: %s\n", address.Hex())

	// (可选) 地址的字节形式
	fmt.Printf("Address Bytes: %x\n", address.Bytes())

	// (可选) EIP-55 校验和格式（默认）
	fmt.Printf("Checksummed Address: %s\n", common.HexToAddress(address.Hex()).Hex())

}
