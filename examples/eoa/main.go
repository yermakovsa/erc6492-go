package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"

	erc6492 "github.com/yermakovsa/erc6492-go"
)

func main() {
	signer := common.HexToAddress("0x6B6aD336c4016653885CeCa2C11Cf6742843298F")
	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature := common.FromHex("0xd6e50e39ab346b4d8a924608953758e52cb7f81944ee5dbae3e00531eadea82c202706b219d251633c65338b701f05d2a61f633b22f2d34b2cca10dd24742c451c")

	result, err := erc6492.VerifyEOA(signer, hash, signature)
	if err != nil {
		log.Fatalf("verify eoa: %v", err)
	}

	fmt.Printf("valid: %t\n", result.Valid)
	fmt.Printf("method: %s\n", result.Method)
}
