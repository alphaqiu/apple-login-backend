package read_pkcs8

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func Read(appleP8 string) (any, error) {
	//appleP8 := "/Users/alpha/Downloads/下载的工作文件/APNS_with_SIGNIN_LT9HU42KJW.p8"
	// 读取 PKCS8 文件内容
	pemData, err := os.ReadFile(appleP8)
	if err != nil {
		return nil, err
	}

	// 解码 PEM 数据块
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	fmt.Printf("Block type: %s\n", block.Type)
	fmt.Printf("Block header: %v\n", block.Headers)

	// 解析私钥
	// It returns a *rsa.PrivateKey,
	// an *ecdsa.PrivateKey,
	// an ed25519.PrivateKey (not a pointer),
	// or an *ecdh.PrivateKey (for X25519).
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// 输出私钥类型
	fmt.Printf("Private Key Type: %T\n", privateKey)
	// Output: *ecdsa.PrivateKey
	return privateKey, nil
}
