package eth_proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	encoding "github.com/hyperledger/burrow/encoding/hex"
	"github.com/hyperledger/burrow/encoding/rlp"
	"github.com/hyperledger/burrow/rpc"
	"github.com/hyperledger/burrow/txs"
	"github.com/xuperchain/xuper-sdk-go/v2/account"
	"google.golang.org/grpc"

	"io"
	mathRand "math/rand"
	"strings"

	"time"

	"math/big"
	"net/http"
	"strconv"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/crypto"

	"github.com/xuperchain/xuperchain/service/pb"
	"github.com/xuperchain/xupercore/bcs/contract/evm"

	"github.com/xuperchain/eth_proxy/types"
	"github.com/xuperchain/xuper-sdk-go/v2/xuper"
)

var ZeroAddress = make([]byte, 20)

const (
	bcName                = "xuper"
	txHashLength          = 66
	blockHashLength       = 66
	AddressLength         = 42
	coinBaseFrom          = "0x000000000000000000000000000000000"
	contracrLength        = 42
	filteredLogBufferSize = 8
	LogsBloomZore         = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

var FilterMap = make(map[string]*types.Filter)
var deadline = 5 * time.Minute

const DEFAULT_NET = 1

// EthService is the rpc server implementation. Each function is an
// implementation of one ethereum json-rpc
// https://github.com/ethereum/wiki/wiki/JSON-RPC
//
// Arguments and return values are formatted as HEX value encoding
// https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
//
// gorilla RPC is the receiver of these functions, they must all take three
// pointers, and return a single error
//
// see godoc for RegisterService(receiver interface{}, name string) error
//
type EthService interface {
	GetCode(r *http.Request, arg *string, reply *string) error
	Call(r *http.Request, args *types.EthArgs, reply *string) error
	SendTransaction(r *http.Request, args *types.EthArgs, reply *string) error

	GetTransactionReceipt(r *http.Request, arg *string, reply *types.TxReceipt) error
	//Accounts(r *http.Request, arg *string, reply *[]string) error
	EstimateGas(r *http.Request, args *types.EthArgs, reply *string) error
	GetBalance(r *http.Request, p *[]string, reply *string) error
	GetBlockByNumber(r *http.Request, p *[]interface{}, reply *types.Block) error
	GetBlockByHash(r *http.Request, p *[]interface{}, reply *types.Block) error
	BlockNumber(r *http.Request, _ *interface{}, reply *string) error
	GetTransactionByHash(r *http.Request, txID *string, reply *types.Transaction) error
	GetTransactionCount(r *http.Request, _ *interface{}, reply *string) error
	GetLogs(*http.Request, *types.GetLogsArgs, *[]types.Log) error
	NewFilter(*http.Request, *types.GetLogsArgs, *string) error
	GetFilterLogs(*http.Request, *string, *[]types.Log) error
	UninstallFilter(*http.Request, *string, *bool) error
	GetFilter(*http.Request, *string, *types.Filter) error
	GasPrice(*http.Request, *string, *string) error
	SendRawTransaction(*http.Request, *string, *string) error
}

type ethService struct {
	xchainClient pb.XchainClient
	//client  xuper-sdk-go client
	xclient     *xuper.XClient
	eventClient pb.EventServiceClient
	//filterClient  pb.EvmFilterClient
	filterMapLock sync.Mutex
	filterMap     map[uint64]interface{}
	filterSeq     uint64
	account       *account.Account
}
type EthServiceConfig struct {
	Host            string
	ContractAccount string
	KeyPath         string
}

func NewEthService(config *EthServiceConfig) (*ethService, error) {

	conn, err := grpc.Dial(config.Host, grpc.WithInsecure(), grpc.WithMaxMsgSize(64<<20-1))
	if err != nil {
		return nil, err
	}

	eventClient := pb.NewEventServiceClient(conn)
	xchainClient := pb.NewXchainClient(conn)
	client, err := xuper.New(config.Host)

	if err != nil {
		return nil, err
	}
	account, err := account.GetAccountFromPlainFile(config.KeyPath)
	if err != nil {
		return nil, err
	}
	err = account.SetContractAccount(config.ContractAccount)
	if err != nil {
		return nil, err
	}
	return &ethService{
		xchainClient: xchainClient,
		eventClient:  eventClient,
		//logger:       logger.Named("ethservice"),
		filterMap: make(map[uint64]interface{}),
		xclient:   client,
		account:   account,
	}, nil
}

//func (s *ethService) Call(r *http.Request, args *types.EthArgs, reply *string) error {
//	response, err := s.query(s.ccid, strip0x(args.To), [][]byte{[]byte(strip0x(args.Data))})
//
//	if err != nil {
//		return fmt.Errorf("Failed to query the ledger: %s", err)
//	}
//
//	// Clients expect the prefix to present in responses
//	*reply = "0x" + hex.EncodeToString(response.Payload)
//
//	return nil
//}
func (s *ethService) SendTransaction(r *http.Request, args *types.EthArgs, reply *string) error {
	// *reply = "0x0111111"
	//
	// method := "SendRawTransaction"
	// args1 := map[string]string{
	// 	"from":      args.From,
	// 	"to":        args.To,
	// 	"gas":       args.Gas,
	// 	"gas_price": args.GasPrice,
	// 	"nonce":     args.Nonce,
	// 	"input":     args.Input,
	// 	"value":     args.Value,
	// 	"r":         args.R,
	// 	"s":         args.S,
	// 	"hash":      args.Hash,
	// }
	//
	// req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args1)
	// if err != nil {
	// 	return err
	// }
	// resp, err := s.xclient.Do(req)
	// if err != nil {
	// 	return err
	// }
	// if resp.ContractResponse.Status > 400 {
	// 	return errors.New("TODO1")
	// }
	return nil
}

func (s *ethService) GetTransactionReceipt(r *http.Request, arg *string, reply *types.TxReceipt) error { //todo
	txHash := *arg
	// if len(txHash) != txHashLength {
	// 	return fmt.Errorf("invalid transaction hash,expect length:%d, but got:%d", txHashLength, len(txHash))
	// }

	method := "GetTransactionReceipt"
	args1 := make(map[string]string)
	args1["tx_hash"] = txHash

	//fmt.Printf("Account:%s\n",s.account.Address)
	req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args1)
	if err != nil {
		return err
	}
	resp, err := s.xclient.PreExecTx(req)
	if err != nil {
		return err
	}

	signedTx := resp.ContractResponse.Body
	data, err := encoding.DecodeToBytes(string(signedTx))
	if err != nil {
		return err
	}

	rawTx := new(rpc.RawTx)
	err = rlp.Decode(data, rawTx)
	if err != nil {
		return err
	}

	result := &types.TxReceipt{}
	//	result.BlockHash = fmt.Sprintf("%x", receipt.TxStatus.Tx.Blockid)
	//	result.BlockNumber = fmt.Sprintf("%d", receipt.BlockNumber)
	//	//reply.ContractAddress
	//	logs := parseEvmLog2TyepLogs(receipt.Log)
	//	result.Logs = logs

	enc, err := txs.RLPEncode(rawTx.Nonce, rawTx.GasPrice, rawTx.GasLimit, rawTx.To, rawTx.Value, rawTx.Data)
	if err != nil {
		return err
	}
	chainID := DEFAULT_NET
	net := uint64(chainID)
	sig := crypto.CompressedSignatureFromParams(rawTx.V-net-8-1, rawTx.R, rawTx.S)
	pub, err := crypto.PublicKeyFromSignature(sig, crypto.Keccak256(enc))
	if err != nil {
		return err
	}
	from := pub.GetAddress()
	result.From = from.String()
	result.To = string(rawTx.To)
	result.TransactionHash = txHash
	// *reply = *result
	return nil
}

// EstimateGas always return 0
func (s *ethService) EstimateGas(r *http.Request, _ *types.EthArgs, reply *string) error {
	*reply = "0x0"
	return nil
}

func (s *ethService) GetTransactionCount(r *http.Request, _ *interface{}, reply *string) error {
	method := "GetTransactionCount"
	args1 := make(map[string]string)

	req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args1)
	if err != nil {
		return err
	}
	resp, err := s.xclient.PreExecTx(req)
	if err != nil {
		return err
	}
	count, ok := new(big.Int).SetString((string(resp.ContractResponse.Body)), 10)
	if !ok {
		return fmt.Errorf("can not convert %s to int ", string(resp.ContractResponse.Body))
	}
	*reply = "0x" + count.Text(16)
	return nil
}

type logger struct {
}

func (s *ethService) Call(r *http.Request, args *types.EthArgs, reply *string) error {
	//l := logging.NewLogger(&logger{})
	//packed, _, err := abi.EncodeFunctionCall(string(rpc.Abi_HelloWorld), "Hello", l)
	//if err != nil {
	//	return err
	//}
	// to := "313131312D2D2D2D2D2D2D2D2D636F756E746572"
	// from := "b60e8dd61c5d32be8058bb8eb970870f07233155"
	// input := "ae896c870000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000678636861696e0000000000000000000000000000000000000000000000000000"
	// method := "ContractCall"
	// args1 := map[string]string{
	// 	"from":  from,
	// 	"to":    to,
	// 	"input": input,
	// 	//"gas":gas,
	// 	//"gas_price":gasPrice
	// }
	// req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args1)
	// if err != nil {
	// 	return err
	// }
	// resp, err := s.xclient.Do(req)
	// if err != nil {
	// 	return err
	// }
	// fmt.Printf("%s\n", resp.Tx.Txid)
	return nil
}
func (s *ethService) SendRawTransaction(r *http.Request, tx *string, reply *string) error {
	method := "SendRawTransaction"
	args := map[string]string{
		"signed_tx": *tx,
	}
	req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args, xuper.WithFee("5000000"))
	if err != nil {
		return err
	}
	resp, err := s.xclient.Do(req)
	if err != nil {
		return err
	}

	*reply = hex.EncodeToString(resp.ContractResponse.Body)
	return nil
}

func (s *ethService) GetBalance(r *http.Request, p *[]string, reply *string) error {
	params := *p
	if len(params) != 2 {
		return fmt.Errorf("need 2 params, got %q", len(params))
	}

	switch params[1] {
	case "latest":
	case "earliest":
		return fmt.Errorf("earliest status query balance is not supported at present")
	case "pending":
		return fmt.Errorf("pending status query balance is not supported at present")
	default:
		return fmt.Errorf("only the latest is supported now")
	}

	address := params[0][2:]

	method := "BalanceOf"
	args := map[string]string{
		"address": address,
	}
	req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args)
	if err != nil {
		return err
	}
	resp, err := s.xclient.PreExecTx(req)
	if err != nil {
		return err
	}
	balance, ok := new(big.Int).SetString(string(resp.ContractResponse.Body), 10)
	if !ok {
		return errors.New("get balance failed")
	}
	*reply = balance.Text(16)
	return nil

}

func (s *ethService) BlockNumber(r *http.Request, _ *interface{}, reply *string) error {
	blockNumber, err := s.parseBlockNum("latest")
	if err != nil {
		return fmt.Errorf("failed to get latest block number: %s", err)
	}
	*reply = "0x" + strconv.FormatUint(blockNumber, 16)
	return nil
}

func (s *ethService) GetBlockByNumber(r *http.Request, p *[]interface{}, reply *types.Block) error {
	params := *p

	numParams := len(params)
	if numParams != 2 {
		return fmt.Errorf("need 2 params, got %q", numParams)
	}
	// first arg is string of block to get
	number, ok := params[0].(string)
	if !ok {
		return fmt.Errorf("Incorrect first parameter sent, must be string")
	}
	if len(number) < 2 || number[:2] != "0x" {
		return fmt.Errorf("please input correct number")
	}

	// second arg is bool for full txn or hash txn
	fullTransactions, ok := params[1].(bool)
	if !ok {
		return fmt.Errorf("Incorrect second parameter sent, must be boolean")
	}

	blockHeight, err := strconv.ParseInt(number[2:], 16, 64)
	if err != nil {
		return fmt.Errorf("Incorrect first parameter sent, invalid block height")
	}

	blockHeightPB := &pb.BlockHeight{
		Header: &pb.Header{
			// Logid: global.Glogid(),
		},
		Bcname: "xuper",
		Height: blockHeight,
	}

	block, err := s.xchainClient.GetBlockByHeight(context.TODO(), blockHeightPB)
	if err != nil {
		return fmt.Errorf("failed to query the ledger: %v", err)
	}

	blk, err := parseBlock(block, fullTransactions)
	if err != nil {
		return err
	}

	*reply = *blk
	return nil
}

func (s *ethService) GetBlockByHash(r *http.Request, p *[]interface{}, reply *types.Block) error {
	params := *p
	if len(params) != 2 {
		return fmt.Errorf("need 2 params, got %q", len(params))
	}
	blockHash, ok := params[0].(string)
	if !ok {
		return fmt.Errorf("Incorrect first parameter sent, must be string")
	}
	if len(blockHash) != blockHashLength {
		return fmt.Errorf("invalid block hash,expect length:%d, but got:%d", txHashLength, len(blockHash))
	}

	fullTransactions, ok := params[1].(bool)
	if !ok {
		return fmt.Errorf("Incorrect second parameter sent, must be boolean")
	}
	block, err := s.getBlockByHash(blockHash, fullTransactions)
	if err != nil {
		return err
	}
	*reply = *block
	return nil
}

func (s *ethService) GetTransactionByHash(r *http.Request, txID *string, reply *types.Transaction) error {
	if len(*txID) != txHashLength {
		return fmt.Errorf("invalid transaction hash,expect length:%d, but got:%d", txHashLength, len(*txID))
	}
	txHash := (*txID)[2:]
	method := "GetTransactionReceipt"
	args1 := make(map[string]string)
	args1["tx_hash"] = txHash

	req, err := xuper.NewInvokeContractRequest(s.account, xuper.Xkernel3Module, "$evm", method, args1)
	if err != nil {
		return err
	}
	resp, err := s.xclient.PreExecTx(req)
	if err != nil {
		return err
	}

	signedTx := resp.ContractResponse.Body
	data, err := encoding.DecodeToBytes(string(signedTx))
	if err != nil {
		return err
	}

	rawTx := new(rpc.RawTx)
	err = rlp.Decode(data, rawTx)
	if err != nil {
		return err
	}

	result := &types.Transaction{}
	//	result.BlockHash = fmt.Sprintf("%x", receipt.TxStatus.Tx.Blockid)
	//	result.BlockNumber = fmt.Sprintf("%d", receipt.BlockNumber)
	//	//reply.ContractAddress
	//	logs := parseEvmLog2TyepLogs(receipt.Log)
	//	result.Logs = logs

	enc, err := txs.RLPEncode(rawTx.Nonce, rawTx.GasPrice, rawTx.GasLimit, rawTx.To, rawTx.Value, rawTx.Data)
	if err != nil {
		return err
	}
	chainID := DEFAULT_NET
	net := uint64(chainID)
	sig := crypto.CompressedSignatureFromParams(rawTx.V-net-8-1, rawTx.R, rawTx.S)
	pub, err := crypto.PublicKeyFromSignature(sig, crypto.Keccak256(enc))
	if err != nil {
		return err
	}
	from := pub.GetAddress()
	result.From = from.String()
	result.To = string(rawTx.To)
	result.Hash = txHash
	// *reply = *result
	//pbTxStatus := &pb.TxStatus{
	//	Header: &pb.Header{
	//		// Logid: global.Glogid(),
	//	},
	//	Bcname: bcName,
	//	Txid:   rawTxId,
	//}
	//txStatus, err := s.xchainClient.QueryTx(context.TODO(), pbTxStatus)
	//if err != nil {
	//	return fmt.Errorf("Get The Transaction Error\n")
	//}
	//if txStatus.Status == pb.TransactionStatus_NOEXIST {
	//	return fmt.Errorf("The Transaction NOT EXIST\n")
	//}
	//
	//if txStatus.Status != pb.TransactionStatus_CONFIRM {
	//	return fmt.Errorf("Get The Transaction Error\n")
	//}
	//
	//tx, err := parseTransaction(txStatus.Tx)
	//if err != nil {
	//	return fmt.Errorf("Can Not Parse The Transaction\n")
	//}
	//
	//block, err := s.getBlockByHash(tx.BlockHash, false)
	//if err != nil {
	//	return fmt.Errorf("Get Block Number Error:%s\n", err.Error())
	//}
	//
	//tx.BlockNumber = block.Number
	// *reply = *result
	return nil
}

func (s *ethService) GetLogs(r *http.Request, args *types.GetLogsArgs, logs *[]types.Log) error {
	if args == nil {
		return fmt.Errorf("Filter can not be nil \n")
	}
	var err error
	logsFrom, err := s.getLogs(args)
	if err != nil {
		return err
	}
	*logs = *logsFrom
	return nil
}

func (s *ethService) getLogs(args *types.GetLogsArgs) (logs *[]types.Log, err error) {
	filter, err := s.specsParams(args)
	if err != nil {
		return nil, err
	}

	buf, _ := proto.Marshal(filter)
	request := &pb.SubscribeRequest{
		Type:   pb.SubscribeType_BLOCK,
		Filter: buf,
	}
	endBlock, err := strconv.ParseInt(args.ToBlock, 10, 64)
	if err != nil {
		return nil, err
	}
	logs, err = s.getEvent(request, endBlock)
	return
}

func (s *ethService) specsParams(args *types.GetLogsArgs) (*pb.BlockFilter, error) {
	latestBlockNumber, err := s.parseBlockNum("latest")
	if err != nil {
		return nil, err
	}

	filter := &pb.BlockFilter{
		Bcname: bcName,
		Range:  &pb.BlockRange{},
	}

	if args.FromBlock == "" {
		args.FromBlock = fmt.Sprintf("%d", latestBlockNumber)
	}
	fromBlock, err := strconv.Atoi(args.FromBlock)
	if err != nil {
		return nil, err
	}
	if fromBlock > int(latestBlockNumber) {
		args.FromBlock = fmt.Sprintf("%d", latestBlockNumber)
	}
	filter.Range.Start = args.FromBlock

	if args.ToBlock == "" {
		args.ToBlock = fmt.Sprintf("%d", latestBlockNumber+1)
	}
	toBlock, err := strconv.Atoi(args.ToBlock)
	if err != nil {
		return nil, err
	}
	if toBlock > int(latestBlockNumber) {
		args.ToBlock = fmt.Sprintf("%d", latestBlockNumber+1)
	}
	filter.Range.End = args.ToBlock

	//if toBlock - fromBlock > 100000 {						// todo 讨论 查询范围不超过100000，为了避免接口返回时间过长
	//	return nil,fmt.Errorf("the range of block should not be more than 100000")
	//}

	if len(args.Address) > 0 {
		name, err := evm2xuper(args.Address[0]) // 暂不支持多个地址查询
		if err != nil {
			return nil, err
		}
		filter.Contract = name
	}
	return filter, nil
}

func (s *ethService) getEvent(req *pb.SubscribeRequest, endBlock int64) (*[]types.Log, error) {
	stream, err := s.eventClient.Subscribe(context.TODO(), req)
	if err != nil {
		return nil, err
	}

	var logs []types.Log

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return nil, err
		}
		if err != nil {
			return nil, err
		}
		var block pb.FilteredBlock
		err = proto.Unmarshal(event.Payload, &block)
		if err != nil {
			return nil, err
		}

		if len(block.GetTxs()) == 0 {
			continue
		}
		for _, tx := range block.GetTxs() {
			if len(tx.Events) == 0 {
				continue
			}
			for _, eventLog := range tx.GetEvents() {
				log := types.Log{}
				contractName := eventLog.Contract
				eventAddr, err := xuper2evm(contractName)
				if err != nil {
					return nil, fmt.Errorf("can not parse the contractName")
				}
				log.Address = eventAddr
				log.Data = string(eventLog.Body)
				log.BlockNumber = fmt.Sprintf("%x", block.GetBlockHeight())
				log.BlockHash = "0x" + block.GetBlockid()
				log.TxHash = "0x" + tx.Txid
				//log.Index
				//log.TxIndex
				logs = append(logs, log)
			}
		}
		if block.BlockHeight >= endBlock-1 {
			return &logs, nil
		}
	}

}

func (s *ethService) NewFilter(r *http.Request, args *types.GetLogsArgs, result *string) error {
	if args == nil {
		return fmt.Errorf("Filter can not be nil\n")
	}
	filterID := generateID()
	filter := &types.Filter{
		*args,
		time.Now().Unix(),
		filterID,
	}

	if _, ok := FilterMap[filterID]; !ok {
		FilterMap[filterID] = filter
	}
	go filterRecycling(filterID) // filter定期回收
	*result = filterID
	return nil
}

func filterRecycling(filterID string) {
	deadDuration := int64(deadline.Seconds())
	ticker := time.NewTicker(deadline)
	for {
		<-ticker.C
		filter := &types.Filter{}
		var ok bool
		if filter, ok = FilterMap[filterID]; !ok {
			return
		}
		timeNow := time.Now().Unix()
		lastUpdateTime := filter.Time
		if (timeNow - lastUpdateTime) > deadDuration {
			delete(FilterMap, filterID)
		}
	}
}

func generateID() string {
	var buf = make([]byte, 8)
	var seed int64
	if _, err := rand.Read(buf); err != nil {
		seed = int64(binary.BigEndian.Uint64(buf))
	} else {
		seed = int64(time.Now().Nanosecond())
	}
	rng := mathRand.New(mathRand.NewSource(seed))
	mu := sync.Mutex{}
	mu.Lock()
	bz := make([]byte, 16)
	rng.Read(bz)

	id := hex.EncodeToString(bz)
	id = strings.TrimLeft(id, "0")
	if id == "" {
		id = "0" // ID's are RPC quantities, no leading zero's and 0 is 0x0.
	}
	return "0x" + id
}

func getFilter(filterID string) (*types.Filter, error) {
	filter := &types.Filter{}
	var ok bool
	if filter, ok = FilterMap[filterID]; !ok {
		return nil, fmt.Errorf("%s filter does not exist，it may have been unused for more than 5 minutes and destroyed", filterID)
	} else {
		filter.Time = time.Now().Unix()
		return filter, nil
	}
}

func (s *ethService) GetFilter(r *http.Request, id *string, logArgs *types.Filter) error {
	if id == nil {
		return fmt.Errorf("FilterID can not be nil")
	}

	filter, err := getFilter(*id)
	if err != nil {
		return err
	}
	logArgs = filter
	return nil
}

func (s *ethService) UninstallFilter(r *http.Request, id *string, ok *bool) error {
	if id == nil {
		return fmt.Errorf("FilterID can not be nil")
	}
	filterID := *id

	if _, exist := FilterMap[filterID]; exist {
		delete(FilterMap, filterID)
		*ok = true
		return nil
	} else {
		return fmt.Errorf("filter: %s not found", filterID)
	}
}

func (s *ethService) GetFilterLogs(r *http.Request, id *string, logs *[]types.Log) error {
	filterID := *id
	filter, err := getFilter(filterID)
	if err != nil {
		return err
	}

	logsFrom, err := s.getLogs(&(filter.GetLogsArgs))
	if err != nil {
		return err
	}
	*logs = *logsFrom
	return nil
}

func (s *ethService) getBlockByHash(blockHash string, fullTransactions bool) (*types.Block, error) {
	rawBlockid, err := hex.DecodeString(blockHash[2:]) // 去掉0x
	if err != nil {
		return nil, fmt.Errorf("invalid blockHash")
	}

	blockId := &pb.BlockID{
		Header: &pb.Header{
			// Logid: global.Glogid(),
		},
		Bcname:      bcName,
		Blockid:     rawBlockid,
		NeedContent: true,
	}

	b, err := s.xchainClient.GetBlock(context.TODO(), blockId)
	if err != nil {
		return nil, fmt.Errorf("failed to query the ledger: %v", err)
	}

	if b.Status == pb.Block_NOEXIST {
		return nil, fmt.Errorf("Block Not Exits\n")
	}
	if b.Status != pb.Block_TRUNK {
		return nil, fmt.Errorf("Query Block Error\n")
	}

	block, err := parseBlock(b, fullTransactions)
	if err != nil {
		return nil, fmt.Errorf("Failed to Query The Block: %s\n", err.Error())
	}
	return block, nil
}

func parseBlock(block *pb.Block, fullTransactions bool) (*types.Block, error) {
	blockHash := "0x" + hex.EncodeToString(block.Block.Blockid)
	blockNumber := "0x" + strconv.FormatUint(uint64(block.Block.CurBlockNum), 16)

	data := block.GetBlock().GetTransactions()
	txns := make([]interface{}, 0, len(data))
	for index, transactionData := range data {
		if transactionData == nil {
			continue
		}

		if fullTransactions { // todo 交易解析
			txn := types.Transaction{
				BlockHash:        blockHash,
				BlockNumber:      blockNumber,
				TransactionIndex: "0x" + strconv.FormatUint(uint64(index), 16),
				Hash:             "0x" + hex.EncodeToString(transactionData.GetTxid()),
			}
			tx, err := parseTransaction(transactionData)
			if err != nil {
				return nil, fmt.Errorf("parse Transaction error")
			}

			txn.To = "0x" + tx.To
			txn.Input = "0x" + tx.Input
			txn.From = tx.From
			txns = append(txns, txn)
		} else {
			txns = append(txns, "0x"+hex.EncodeToString(transactionData.GetTxid()))
		}
	}

	blk := &types.Block{
		BlockData: types.BlockData{
			Number:     blockNumber,
			Hash:       blockHash,
			ParentHash: "0x" + hex.EncodeToString(block.Block.PreHash),
			//TransactionsRoot:string(block.Block.MerkleRoot),		//todo merkerRoot是一个[][]byte
			Miner: string(block.Block.Proposer),
			// todo 复用了以太坊过滤器的零值,512位，这里是否真的需要这么长
			LogsBloom:  LogsBloomZore,
			Difficulty: fmt.Sprintf("0x%x", block.Block.TargetBits),
			//GasUsed:
			Timestamp: "0x" + strconv.FormatInt(block.Block.Timestamp/100000000, 16), //时间戳修改为秒为单位，此处/100000000
		},
		Transactions: txns,
	}
	return blk, nil
}

func (s *ethService) parseBlockNum(input string) (uint64, error) {
	bcStatusPB := &pb.BCStatus{
		Header: &pb.Header{
			// Logid: global.Glogid(),
		},
		Bcname: "xuper",
	}
	switch input {
	case "latest":
		// latest
		bcStatus, err := s.xchainClient.GetBlockChainStatus(context.TODO(), bcStatusPB)
		if err != nil {
			return 0, fmt.Errorf("failed to query the ledger: %v", err)
		}
		topBlockNumber := uint64(bcStatus.GetBlock().GetHeight())
		return topBlockNumber, nil
	case "earliest":
		return 0, nil
	case "pending":
		return 0, fmt.Errorf("unsupported: fabric does not have the concept of in-progress blocks being visible")
	default:
		return strconv.ParseUint(input, 16, 64)
	}
}
func (s *ethService) GasPrice(r *http.Request, arg *string, reply *string) error {
	*reply = "0"
	return nil
}

func (s *ethService) GetCode(r *http.Request, arg *string, reply *string) error {
	if len(*arg) != contracrLength {
		return fmt.Errorf("Invalid Transaction Hash,Expect Length:%d, But Got:%d\n", contracrLength, len(*arg))
	}
	evmAddrStr := *arg
	name, err := evm2xuper(evmAddrStr)
	if err != nil {
		return err
	}
	_ = name
	*reply = "0x600160008035811a818181146012578301005b601b6001356025565b8060005260206000f25b600060078202905091905056"

	//pbContractParams := &pb.ContractParams{
	//	Header: &pb.Header{
	//		Logid: global.Glogid(),
	//	},
	//	Bcname: "xuper",
	//	Name:   name,
	//}
	//contractParams, err := s.xchainClient.GetContractParams(context.TODO(), pbContractParams)
	//if err != nil {
	//	s.logger.Error(err)
	//	return fmt.Errorf("Can Not Get the Code\n")
	//}
	//*reply = string(contractParams.Code)
	return nil

}

func parseTransaction(tx *pb.Transaction) (*types.Transaction, error) {
	from := tx.Initiator
	if tx.Coinbase {
		from = coinBaseFrom
	}
	to := ""
	valueTotal := big.NewInt(0)
	feeTotal := big.NewInt(0)
	for _, output := range tx.TxOutputs {
		if string(output.ToAddr) != from && string(output.ToAddr) != "$" {
			to = string(output.ToAddr) // todo 如果有多个地址怎么办
			val := big.NewInt(0).SetBytes(output.Amount)
			valueTotal = valueTotal.Add(valueTotal, val)
		}
		if string(output.ToAddr) == "$" {
			val := big.NewInt(0).SetBytes(output.Amount)
			feeTotal = feeTotal.Add(feeTotal, val)
		}
	}
	blockHash := "0x" + hex.EncodeToString(tx.Blockid)
	txHash := "0x" + hex.EncodeToString(tx.Txid)

	type InvokeRequest struct {
		ModuleName   string            `json:"moduleName"`
		ContractName string            `json:"contractName"`
		MethodName   string            `json:"methodName"`
		Args         map[string]string `json:"args"` // resourceLimit没有记录
	}

	tmpReq := InvokeRequest{}
	if tx.ContractRequests != nil {
		for i := 0; i < len(tx.ContractRequests); i++ {
			req := tx.ContractRequests[i]
			tmpReq.ModuleName = req.ModuleName
			tmpReq.ContractName = req.ContractName
			tmpReq.MethodName = req.MethodName
			tmpReq.Args = map[string]string{}
			for argKey, argV := range req.Args {
				tmpReq.Args[argKey] = string(argV)
			}
		}
	}
	bz, err := json.MarshalIndent(tmpReq, "", "")
	if err != nil {
		return nil, fmt.Errorf("Marshal input error\n")
	}

	transaction := &types.Transaction{
		BlockHash: blockHash,
		//BlockNumber:"0",
		Hash:             txHash,
		From:             from,
		To:               to,
		TransactionIndex: "0", // 暂不支持
		Input:            string(bz),
		Gas:              feeTotal.String(),
		GasPrice:         "0x1",
		Value:            valueTotal.String(),
	}
	return transaction, nil
}

func evm2xuper(evmAddrStr string) (string, error) {
	evmAddr, err := crypto.AddressFromHexString(evmAddrStr[2:])
	if err != nil {
		return "", fmt.Errorf("can not parse the string address to evm address")
	}
	name, _, err := evm.DetermineEVMAddress(evmAddr)
	if err != nil {
		return "", fmt.Errorf("can not parse the evm address to contract name")
	}
	return name, nil
}

func xuper2evm(name string) (string, error) {
	addr, _, err := evm.DetermineXchainAddress(name)
	if err != nil {
		return "", err
	}
	return "0x" + addr, nil
}
