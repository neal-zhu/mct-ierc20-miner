package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli"
)

var (
	app         *cli.App = cli.NewApp()
	blockNumber uint64
)

type Sol struct {
	tx *types.Transaction
	bn uint64
}

func init() {
	app.Name = "IERC20 Miner"
	app.Author = "MCT"
	app.Version = "1.0.0"
	app.Commands = []cli.Command{
		{
			Name:  "mine",
			Usage: "mine",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "rpc",
					Value: "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
					Usage: "rpc url",
				},
				&cli.StringFlag{
					Name:  "ticker",
					Value: "",
					Usage: "IERC Ticker",
				},
				&cli.StringFlag{
					Name:  "diff",
					Value: "",
					Usage: "difficulty",
				},
				&cli.StringFlag{
					Name:  "pk",
					Value: "",
					Usage: "PrivateKey",
				},
				&cli.Float64Flag{
					Name:  "maxFee",
					Value: 0,
					Usage: "MaxFeePerGas",
				},
				&cli.Float64Flag{
					Name:  "priorityFee",
					Value: 0,
					Usage: "MaxPriorityFeePerGas",
				},
				&cli.Int64Flag{
					Name:  "n",
					Value: 1,
					Usage: "Number of executions",
				},
			},
			Action: mine,
		},
	}

}
func main() {

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

}
func mine(ctx *cli.Context) error {
	if ctx.String("rpc") == "" {
		fmt.Fprintln(os.Stderr, "Please enter rpc url!")
		return nil

	}
	if ctx.String("ticker") == "" {
		fmt.Fprintln(os.Stderr, "Please enter ticker!")
		return nil
	}
	if ctx.String("diff") == "" {
		fmt.Fprintln(os.Stderr, "Please enter difficulty!")
		return nil
	}
	if ctx.String("pk") == "" {
		fmt.Fprintln(os.Stderr, "Please enter privateKey!")
		return nil
	}
	config := &MineCfg{
		RPC:         ctx.String("rpc"),
		Ticker:      ctx.String("ticker"),
		DIfficulty:  ctx.String("diff"),
		PrivateKey:  ctx.String("pk"),
		Amount:      ctx.Int64("amount"),
		MaxFee:      ctx.Float64("maxFee"),
		PriorityFee: ctx.Float64("priorityFee"),
	}
	go func() {
		// udpate block number
		client, err := ethclient.Dial(config.RPC)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Rpc connect error "+err.Error())
			return
		}
		defer client.Close()
		for {
			bn, err := client.BlockNumber(context.Background())
			if err != nil {
				continue
			}
			atomic.StoreUint64(&blockNumber, bn)
			time.Sleep(5 * time.Second)
		}
	}()
	for i := 0; i < int(ctx.Float64("n")); i++ {
		fmt.Println(fmt.Sprintf("====================================================== %d ======================================================", i+1))
		if err := startMine(config); err != nil {
			log.Println("mine error", err)
		}
		//time.Sleep(5 * time.Second)
	}
	return nil

}

type MineCfg struct {
	RPC         string
	Ticker      string
	DIfficulty  string
	PrivateKey  string
	Amount      int64
	MaxFee      float64
	PriorityFee float64
}

func rlpEnc(v any) []byte {
	w := bytes.NewBuffer(nil)
	rlp.Encode(w, v)
	return w.Bytes()
}

func printTx(tx *types.Transaction) {
	//fmt.Println("Nonce: ", tx.Nonce())
	//fmt.Println("GasPrice: ", tx.GasPrice())
	//fmt.Println("Gas: ", tx.Gas())
	//fmt.Println("To: ", tx.To().Hex())
	//fmt.Println("Value: ", tx.Value())
	//fmt.Println("Data: ", hex.EncodeToString(tx.Data()))
	v, r, s := tx.RawSignatureValues()
	fmt.Println("V: ", hex.EncodeToString(rlpEnc(v)))
	fmt.Println("R: ", hex.EncodeToString(rlpEnc(r)))
	fmt.Println("S: ", hex.EncodeToString(rlpEnc(s)))
	fmt.Println("Hash: ", tx.Hash().Hex())

	data, _ := rlp.EncodeToBytes(tx)
	fmt.Println("RLP: ", hex.EncodeToString(data))
}

func startMine(cfg *MineCfg) error {

	client, err := ethclient.Dial(cfg.RPC)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Rpc connect error "+err.Error())
		return nil
	}
	defer client.Close()
	gas, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		panic(err)
	}
	ticker := cfg.Ticker
	privateKey := strings.ReplaceAll(cfg.PrivateKey, "0x", "")
	pk, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		panic(err)
		//log.Fatal(err)
	}
	publicKey := pk.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("error casting public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	log.Println("Wallet: ", fromAddress.Hex())
	log.Println("Ticker: ", ticker)
	log.Println("Difficulty: ", cfg.DIfficulty)
	log.Println("Amount: ", cfg.Amount)
	maxFee := cfg.MaxFee
	maxFeePerGas := (&big.Int{}).Mul((&big.Int{}).Div(gas, big.NewInt(100)), big.NewInt(150))
	maxPriorityFeePerGas := (&big.Int{}).Div((&big.Int{}).Mul(gas, big.NewInt(15)), big.NewInt(100))
	if maxFee != 0 {
		maxFeePerGas = ToWei(maxFee, 9)
	}
	priorityFee := cfg.PriorityFee
	if priorityFee != 0 {
		maxPriorityFeePerGas = ToWei(priorityFee, 9)
	}
	nonce, err := client.NonceAt(context.Background(), fromAddress, nil)
	if err != nil {
		log.Fatalf("NonceAt error: %v", err)
	}
	log.Println("MaxFee: ", ToDecimal(maxFeePerGas, 9).String(), "Gwei", ", Priority Fee: ", ToDecimal(maxPriorityFeePerGas, 9).String(), "Gwei")
	nullAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")
	var total int64 = 0

	threadCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	numThread := runtime.NumCPU()
	inscribeTx := make(chan Sol, numThread)
	generateReport := make(chan int, numThread)
	for i := 0; i < numThread; i++ {
		go func(i int) {
			var sha = crypto.NewKeccakState()
			id := 0
			generated := 0
			signer := types.LatestSignerForChainID(big.NewInt(1))
			var (
				bn      uint64
				rlpData []byte
			)
			for {
				bn = atomic.LoadUint64(&blockNumber)
				if bn != 0 {
					break
				}
			}

			nonceStr := fmt.Sprintf("%020s", fmt.Sprintf("%d%d", 0, 0))
			callData := fmt.Sprintf(`data:application/json,{"p":"ierc-pow","op":"mint","tick":"%s","block":"%d","nonce":"%s"}`, ticker, bn, nonceStr)
			r, _ := new(big.Int).SetString("56950464317369334027208064042576072815920500984782267917076891192816636520127", 10)
			innerTx := &types.DynamicFeeTx{
				ChainID:   big.NewInt(1),
				Nonce:     nonce,
				GasFeeCap: maxFeePerGas,
				GasTipCap: maxPriorityFeePerGas,
				To:        &nullAddress,
				Value:     big.NewInt(0),
				Data:      []byte(callData),
				Gas:       25000,
				V:         big.NewInt(1),
				R:         r,
				S:         r,
			}
			tx := types.NewTx(innerTx)
			w := bytes.NewBuffer(nil)
			w.Write([]byte{tx.Type()})
			rlp.Encode(w, []interface{}{
				tx.ChainId(),
				tx.Nonce(),
				tx.GasTipCap(),
				tx.GasFeeCap(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(),
			})
			//tx.EncodeRLP(w)
			rlpData = w.Bytes()
			callDataIndex := bytes.Index(rlpData, []byte(callData))

			w = bytes.NewBuffer(nil)
			w.Write([]byte{tx.Type()})
			rlp.Encode(
				w, innerTx,
			)
			txRlpData := w.Bytes()
			txCallDataIndex := bytes.Index(txRlpData, []byte(callData))

			for {
				select {
				case <-threadCtx.Done():
					log.Println("stop")
					return
				default:
					bn := atomic.LoadUint64(&blockNumber)
					nonceStr = fmt.Sprintf("%020s", fmt.Sprintf("%d%d", i, id))
					callData = fmt.Sprintf(`data:application/json,{"p":"ierc-pow","op":"mint","tick":"%s","block":"%d","nonce":"%s"}`, ticker, bn, nonceStr)
					// 计算签名
					copy(rlpData[callDataIndex:], []byte(callData))
					sha.Reset()
					sha.Write(rlpData)
					// 02f8df 0129849266aaea8505b802acde8261a894000000000000000000000000000000000000000080b873646174613a6170706c69636174696f6e2f6a736f6e2c7b2270223a22696572632d706f77222c226f70223a226d696e74222c227469636b223a226574687069222c22626c6f636b223a223138393936383030222c226e6f6e6365223a223030303030303030303030303030303030303030227dc0
					// 02f89c 0129849266aaea8505b802acde8261a894000000000000000000000000000000000000000080b873646174613a6170706c69636174696f6e2f6a736f6e2c7b2270223a22696572632d706f77222c226f70223a226d696e74222c227469636b223a226574687069222c22626c6f636b223a223138393936383030222c226e6f6e6365223a223030303030303030303030303030303030303030227dc0
					var hash common.Hash
					sha.Read(hash[:])
					sig, err := crypto.Sign(hash[:], pk)
					if err != nil {
						log.Fatalf("Sign error: %v", err)
					}
					r, s, v, err := signer.SignatureValues(tx, sig)
					//fmt.Printf("V %x\n", rlpEnc(v))
					//fmt.Printf("R %x\n", rlpEnc(r))
					//fmt.Printf("S %x\n", rlpEnc(s))
					if err != nil {
						log.Fatalf("SignatureValues error: %v", err)
					}

					buf := bytes.NewBuffer(nil)
					rlp.Encode(buf, v)
					rlp.Encode(buf, r)
					rlp.Encode(buf, s)
					sha.Reset()

					copy(txRlpData[txCallDataIndex:], []byte(callData))
					copy(txRlpData[len(txRlpData)-buf.Len():], buf.Bytes())
					sha.Write(txRlpData)
					sha.Read(hash[:])
					if strings.HasPrefix(hash.String(), cfg.DIfficulty) {
						{
							tx := types.NewTx(&types.DynamicFeeTx{
								ChainID:   big.NewInt(1),
								Nonce:     nonce,
								GasFeeCap: maxFeePerGas,
								GasTipCap: maxPriorityFeePerGas,
								To:        &nullAddress,
								Value:     big.NewInt(0),
								Data:      []byte(callData),
								Gas:       25000,
							})
							tx, err := types.SignTx(tx, signer, pk)
							if err != nil {
								log.Fatalf("SignTx error: %v", err)
							}
							vv, rr, ss := tx.RawSignatureValues()
							if vv.Cmp(v) != 0 || rr.Cmp(r) != 0 || ss.Cmp(s) != 0 {
								log.Fatalf("SignTx error: rsv not equal")
							}
							xhash := tx.Hash()
							printTx(tx)
							if !bytes.Equal(xhash[:], hash[:]) {
								log.Fatalf("hash error: %x %x", xhash, hash)
							}
							log.Println("hash", hash.String())
						}
						cbn, err := client.BlockNumber(context.Background())
						if err != nil {
							continue
						}
						if cbn-bn > 5 {
							log.Println("BlockNumber", bn, "too stale", cbn)
							continue
						}
						inscribeTx <- Sol{
							tx: tx,
							bn: bn,
						}
					}
					id++
					generated++
					if generated >= 1000 {
						generateReport <- generated
						generated = 0
					}
				}
			}
		}(i)
	}
	intervalTicker := time.Tick(5 * time.Second)
	for {
		select {
		case <-intervalTicker:
			fmt.Printf("%d/s \n", total/5)
			total = 0
		case generated := <-generateReport:
			total += int64(generated)
		case inscribeTx := <-inscribeTx:
			log.Println("Inscribe tx", inscribeTx.tx.Hash().String(), "bn", inscribeTx.bn)
			if err := client.SendTransaction(context.Background(), inscribeTx.tx); err != nil {
				return fmt.Errorf("SendTransaction error: %w", err)
			}
			for i := 0; i < 10; i++ {
				_, err := client.TransactionReceipt(context.Background(), inscribeTx.tx.Hash())
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}
				log.Println("Success", inscribeTx.tx.Hash().String())
				break
			}
			return nil
		}

	}
	return nil
}
func stringToHex(input string) string {
	// Convert the string to a byte slice
	bytes := []byte(input)

	// Use the hex package to encode the byte slice to a hexadecimal string
	hexString := hex.EncodeToString(bytes)

	return hexString
}
func ToDecimal(ivalue interface{}, decimals int) decimal.Decimal {
	value := new(big.Int)
	switch v := ivalue.(type) {
	case string:
		value.SetString(v, 10)
	case *big.Int:
		value = v
	}

	mul := decimal.NewFromFloat(float64(10)).Pow(decimal.NewFromFloat(float64(decimals)))
	num, _ := decimal.NewFromString(value.String())
	result := num.Div(mul)

	return result
}

func ToWei(iamount interface{}, decimals int) *big.Int {
	amount := decimal.NewFromFloat(0)
	switch v := iamount.(type) {
	case string:
		amount, _ = decimal.NewFromString(v)
	case float64:
		amount = decimal.NewFromFloat(v)
	case int64:
		amount = decimal.NewFromFloat(float64(v))
	case decimal.Decimal:
		amount = v
	case *decimal.Decimal:
		amount = *v

	}

	mul := decimal.NewFromFloat(float64(10)).Pow(decimal.NewFromFloat(float64(decimals)))
	result := amount.Mul(mul)
	wei := new(big.Int)
	wei.SetString(result.String(), 10)

	return wei
}
