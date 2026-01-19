package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	rand2 "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func SignECDSA(private *big.Int, data string) (string, string, error) {
	privateKey, err := crypto.ToECDSA(private.Bytes())
	if err != nil {
		log.Fatalf("to ECDSA failed: %v", err)
	}
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand2.Reader, privateKey, hash[:])
	if err != nil {
		return "", "", err
	}
	r1 := hex.EncodeToString(r.Bytes())
	s1 := hex.EncodeToString(s.Bytes())
	return r1, s1, nil
}

func SignECDSA_v2(private *big.Int, data string) (string, string, error) {
	privateKey := &ecdsa.PrivateKey{}
	privateKey.Curve = elliptic.P256()
	privateKey.D = private
	x, y := elliptic.P256().ScalarBaseMult(private.Bytes())
	privateKey.X = x
	privateKey.Y = y
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand2.Reader, privateKey, hash[:])
	if err != nil {
		return "", "", err
	}
	r1 := hex.EncodeToString(r.Bytes())
	s1 := hex.EncodeToString(s.Bytes())
	return r1, s1, nil
}

// keccak256 helper
func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// 生成新的私钥（secp256k1）
func generateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// 从私钥导出 0x-prefixed hex 私钥（64 hex chars）
func privateKeyToHex(priv *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.FromECDSA(priv))
}

// 从私钥导出公钥（未压缩，去掉 0x04 前缀后的 64 字节）hex
func publicKeyToHex(priv *ecdsa.PrivateKey) string {
	pubBytes := crypto.FromECDSAPub(&priv.PublicKey) // includes 0x04 prefix
	// 去掉前缀 0x04（一个字节）
	if len(pubBytes) == 65 && pubBytes[0] == 0x04 {
		return hex.EncodeToString(pubBytes[1:])
	}
	return hex.EncodeToString(pubBytes)
}

// 从公钥计算地址（0x + last 20 bytes of Keccak256(pubKey[1:])）
func addressFromPub(priv *ecdsa.PrivateKey) string {
	pubBytes := crypto.FromECDSAPub(&priv.PublicKey) // 65 bytes, first is 0x04
	if len(pubBytes) != 65 {
		return ""
	}
	hash := keccak256(pubBytes[1:]) // drop 0x04
	// last 20 bytes
	addr := hash[12:]
	return "0x" + hex.EncodeToString(addr)
}

// 直接对 32-byte hash 进行签名（返回 65 字节 signature，其中最后一字节是 v(0/1/27/28) 取决实现）
// go-ethereum 的 Sign 返回 [R||S||V] 其中 V 是 0/1 (需要 +27 做以太坊常见表示)。
func signHash(priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	return crypto.Sign(hash, priv) // 返回 65 字节
}

// 验证签名：方法一，使用公钥直接验证（ecdsa.Verify）
// 注意：crypto.Sign 产生的 signature 的最后一字节 v = 0 or 1。
// 要用 ecdsa.Verify，需要把 signature 拆成 r,s。
func VerifyWithPub(pub *ecdsa.PublicKey, hash []byte, sig []byte) bool {
	// 从 sig 拆 r,s（sig 前 64 字节）
	if len(sig) < 64 {
		return false
	}
	// 使用 go-ethereum 的 ECDSA 验证工具:
	return crypto.VerifySignature(crypto.FromECDSAPub(pub)[1:], hash, sig[:64])
	// 说明: VerifySignature 期望 uncompressed pubkey WITHOUT 0x04 prefix (64 bytes), hash, and sig (r||s).
}

// 验证签名：方法二，从签名恢复公钥并比较地址
func verifyByRecoverAndCompareAddress(hash []byte, sig []byte, expectedAddr string) (bool, error) {
	if len(sig) != 65 {
		return false, fmt.Errorf("signature must be 65 bytes")
	}
	// Recover public key
	pubKey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return false, err
	}
	// derive address
	recoveredAddr := "0x" + hex.EncodeToString(keccak256(crypto.FromECDSAPub(pubKey)[1:])[12:])
	return recoveredAddr == expectedAddr, nil
}

// personal_sign: 对任意消息做 Ethereum 前缀并 keccak256，然后签名
func PersonalSign(priv *ecdsa.PrivateKey, message []byte) ([]byte, []byte, error) {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	prefixed := append([]byte(prefix), message...)
	hash := keccak256(prefixed)
	sig, err := signHash(priv, hash)
	return sig, hash, err
}

func TestSign(t *testing.T) {
	// 生成私钥
	priv, err := generateKey()
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	privHex := privateKeyToHex(priv)
	pubHex := publicKeyToHex(priv)
	addr := addressFromPub(priv)

	fmt.Println("Private key (hex):", privHex)
	fmt.Println("Public key (hex, 64 bytes x||y):", pubHex)
	fmt.Println("Address:", addr)

	// 要签名的消息（示例）
	message := []byte("hello ethereum")

	// 使用 personal_sign 流程（更接近以太坊 wallet 的签名）
	sig, hash, err := PersonalSign(priv, message)
	if err != nil {
		log.Fatalf("personal sign: %v", err)
	}
	fmt.Println("\n--- personal_sign 流程 ---")
	fmt.Printf("Message: %s\n", string(message))
	fmt.Println("Prefixed hash (hex):", hex.EncodeToString(hash))
	fmt.Println("Signature (hex, r||s||v):", hex.EncodeToString(sig))

	// 验证方法一：直接用公钥验证（注意：VerifySignature 需要 r||s，不需要 v）
	ok := VerifyWithPub(&priv.PublicKey, hash, sig)
	fmt.Println("Verify with public key (r||s):", ok)

	// 验证方法二：从签名恢复公钥并比较地址
	ok2, err := verifyByRecoverAndCompareAddress(hash, sig, addr)
	if err != nil {
		log.Fatalf("verify recover: %v", err)
	}
	fmt.Println("Verify by recovered address equals signer address:", ok2)

	// 示例：如果你只想对 32-byte hash 直接签名（比如交易签名前的 hash），可以：
	randomHash := make([]byte, 32)
	_, _ = rand.Read(randomHash)
	sig2, _ := signHash(priv, randomHash)
	fmt.Println("\nRaw-hash signature (hex):", hex.EncodeToString(sig2))
	// 验证 raw-hash 签名
	ok3 := VerifyWithPub(&priv.PublicKey, randomHash, sig2)
	fmt.Println("Verify raw-hash signature:", ok3)
}
