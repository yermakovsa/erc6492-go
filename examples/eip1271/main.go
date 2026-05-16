package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	erc6492 "github.com/yermakovsa/erc6492-go"
)

func main() {
	rpcURL := os.Getenv("RPC_URL")
	if rpcURL == "" {
		log.Fatal("RPC_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		log.Fatalf("connect rpc: %v", err)
	}
	defer client.Close()

	wallet := common.HexToAddress("0x01719b210cca35ee34f46007daed7fb359086f91")
	hash := common.HexToHash("0x3dec0f6a98cd6082f478ae1d655bf12eb7c2c52be60e011c91a5ae1f62670b5c")
	signature := common.FromHex("0xae49e3481e4a9f5c59d78d3e47efd9cc5975e0c0678243202846eb9e43230e02425fe69fd882ccec3a76e13d25a542b58a33ef24c5a8a8186778d7e13c87ca671c")

	result, err := erc6492.VerifyEIP1271(ctx, client, wallet, hash, signature)
	if err != nil {
		log.Fatalf("verify eip1271: %v", err)
	}

	fmt.Printf("valid: %t\n", result.Valid)
	fmt.Printf("method: %s\n", result.Method)
}
