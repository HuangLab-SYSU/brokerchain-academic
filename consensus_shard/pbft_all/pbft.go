// The pbft consensus process

package pbft_all

import (
	"blockEmulator/chain"
	"blockEmulator/consensus_shard/pbft_all/dataSupport"
	"blockEmulator/consensus_shard/pbft_all/pbft_log"
	"blockEmulator/global"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/shard"
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

type PbftConsensusNode struct {
	// the local config about pbft
	RunningNode *shard.Node // the node information
	ShardID     uint64      // denote the ID of the shard (or pbft), only one pbft consensus in a shard
	NodeID      uint64      // denote the ID of the node in the pbft (shard)

	// the data structure for blockchain
	CurChain *chain.BlockChain // all node in the shard maintain the same blockchain
	db       ethdb.Database    // to save the mpt

	// the global config about pbft
	pbftChainConfig *params.ChainConfig          // the chain config in this pbft
	ip_nodeTable    map[uint64]map[uint64]string // denote the ip of the specific node
	node_nums       uint64                       // the number of nodes in this pfbt, denoted by N
	malicious_nums  uint64                       // f, 3f + 1 = N

	// view change
	view           atomic.Int32 // denote the view of this pbft, the main node can be inferred from this variant
	lastCommitTime atomic.Int64 // the time since last commit.
	lastCommitTime2 atomic.Int64 // the time since last commit.
	viewchangecount atomic.Int32
	viewChangeMap  map[ViewChangeData]map[uint64]bool
	newViewMap     map[ViewChangeData]map[uint64]bool

	// the control message and message checking utils in pbft
	sequenceID        uint64                          // the message sequence id of the pbft
	stopSignal        atomic.Bool                     // send stop signal
	pStop             chan uint64                     // channle for stopping consensus
	requestPool       map[string]*message.Request     // RequestHash to Request
	cntPrepareConfirm map[string]map[*shard.Node]bool // count the prepare confirm message, [messageHash][Node]bool
	cntCommitConfirm  map[string]map[*shard.Node]string // count the commit confirm message, [messageHash][Node]bool
	isCommitBordcast  map[string]bool                 // denote whether the commit is broadcast
	isReply           map[string]bool                 // denote whether the message is reply
	height2Digest     map[uint64]string               // sequence (block height) -> request, fast read

	// pbft stage wait
	pbftStage              atomic.Int32 // 1->Preprepare, 2->Prepare, 3->Commit, 4->Done
	pbftLock               sync.Mutex
	conditionalVarpbftLock sync.Cond

	// locks about pbft
	sequenceLock sync.Mutex // the lock of sequence
	lock         sync.Mutex // lock the stage
	askForLock   sync.Mutex // lock for asking for a serise of requests

	// seqID of other Shards, to synchronize
	seqIDMap   map[uint64]uint64
	seqMapLock sync.Mutex

	// logger
	pl *pbft_log.PbftLog
	// tcp control
	tcpln       net.Listener
	tcpPoolLock sync.Mutex

	// to handle the message in the pbft
	ihm ExtraOpInConsensus

	// to handle the message outside of pbft
	ohm OpInterShards
	lastbeattime time.Time
}

// generate a pbft consensus for a node
func NewPbftNode(shardID, nodeID uint64, pcc *params.ChainConfig, messageHandleType string) *PbftConsensusNode {
	p := new(PbftConsensusNode)
	p.ip_nodeTable = params.IPmap_nodeTable
	p.node_nums = pcc.Nodes_perShard
	p.ShardID = shardID
	p.NodeID = nodeID
	p.pbftChainConfig = pcc
	//fp := params.DatabaseWrite_path + "mptDB/ldb/s" + strconv.FormatUint(shardID, 10) + "/n" + strconv.FormatUint(nodeID, 10)+ uuid.New().String()
	rr:=uuid.New().String()
	fp := params.DatabaseWrite_path + "mptDB/" + rr

	//if _, err := os.Stat(fp); err == nil {
	//	err2 := os.RemoveAll(fp)
	//	if err2 != nil {
	//		fmt.Println(err2)
	//	}
	//}

	var err error
	p.db, err = rawdb.NewLevelDBDatabase(fp, 0, 1, "accountState", false)
	if err != nil {
		log.Panic(err)
	}
	p.CurChain, err = chain.NewBlockChain2(pcc, p.db,rr)
	if err != nil {
		log.Panic("cannot new a blockchain")
	}

	p.RunningNode = &shard.Node{
		NodeID:  nodeID,
		ShardID: shardID,
		IPaddr:  p.ip_nodeTable[shardID][nodeID],
	}

	global.MyIp = p.ip_nodeTable[shardID][nodeID]

	p.stopSignal.Store(false)
	p.sequenceID = p.CurChain.CurrentBlock.Header.Number + 1
	p.pStop = make(chan uint64)
	p.requestPool = make(map[string]*message.Request)
	p.cntPrepareConfirm = make(map[string]map[*shard.Node]bool)
	p.cntCommitConfirm = make(map[string]map[*shard.Node]string)
	p.isCommitBordcast = make(map[string]bool)
	p.isReply = make(map[string]bool)
	p.height2Digest = make(map[uint64]string)
	p.malicious_nums = (p.node_nums - 1) / 3

	// init view & last commit time
	p.view.Store(0)
	p.viewchangecount.Store(0)
	p.lastCommitTime.Store(time.Now().Add(time.Second * 10).UnixMilli())
	p.lastCommitTime2.Store(time.Now().Add(time.Second * 10).UnixMilli())
	p.viewChangeMap = make(map[ViewChangeData]map[uint64]bool)
	p.newViewMap = make(map[ViewChangeData]map[uint64]bool)

	p.seqIDMap = make(map[uint64]uint64)

	p.pl = pbft_log.NewPbftLog(shardID, nodeID)
	p.lastbeattime = time.Now()

	// choose how to handle the messages in pbft or beyond pbft
	switch string(messageHandleType) {
	case "CLPA_Broker":
		ncdm := dataSupport.NewCLPADataSupport()
		p.ihm = &CLPAPbftInsideExtraHandleMod_forBroker{
			pbftNode: p,
			cdm:      ncdm,
		}
		p.ohm = &CLPABrokerOutsideModule{
			pbftNode: p,
			cdm:      ncdm,
		}
	case "CLPA":
		ncdm := dataSupport.NewCLPADataSupport()
		p.ihm = &CLPAPbftInsideExtraHandleMod{
			pbftNode: p,
			cdm:      ncdm,
		}
		p.ohm = &CLPARelayOutsideModule{
			pbftNode: p,
			cdm:      ncdm,
		}
	case "Broker":
		p.ihm = &RawBrokerPbftExtraHandleMod{
			pbftNode: p,
		}
		p.ohm = &RawBrokerOutsideModule{
			pbftNode: p,
		}
	default:
		p.ihm = &RawRelayPbftExtraHandleMod{
			pbftNode: p,
		}
		p.ohm = &RawRelayOutsideModule{
			pbftNode: p,
		}
	}

	// set pbft stage now
	p.conditionalVarpbftLock = *sync.NewCond(&p.pbftLock)
	p.pbftStage.Store(1)

	return p
}

// handle the raw message, send it to corresponded interfaces
func (p *PbftConsensusNode) handleMessage(msg []byte) {
	msgType, content := message.SplitMessage(msg)
	switch msgType {
	// pbft inside message type
	case message.CPrePrepare:
		// use "go" to start a go routine to handle this message, so that a pre-arrival message will not be aborted.
		go p.handlePrePrepare(content)
	case message.CPrepare:
		// use "go" to start a go routine to handle this message, so that a pre-arrival message will not be aborted.
		go p.handlePrepare(content)
	case message.CCommit:
		// use "go" to start a go routine to handle this message, so that a pre-arrival message will not be aborted.
		go p.handleCommit(content)

	case message.ViewChangePropose:
		p.handleViewChangeMsg(content)
	case message.NewChange:
		p.handleNewViewMsg(content)

	case message.CRequestOldrequest:
		p.handleRequestOldSeq(content)
	case message.CSendOldrequest:
		p.handleSendOldSeq(content)

	case message.CStop:
		p.WaitToStop()
	case message.CPing:
		break

	case message.CShardChange:
		{
			config := new(DynamicConfig)
			err := json.Unmarshal(content, config)
			if err != nil {
				log.Panic()
			}
			fmt.Println("receive shard change msg")
			maxShardId, _ := strconv.Atoi(config.NewNodeinfos[len(config.NewNodeinfos)-1].ShardID)
			shardNum := maxShardId + 1
			params.ShardNum = shardNum

			p.CurChain.ChainConfig.ShardNums = uint64(params.ShardNum)

			nodeNum := len(config.NewNodeinfos)

			nodes := make([]NodeInfo, 0)
			//if config.OldNodeinfos!=nil{
			//	nodes = append(nodes,config.OldNodeinfos...)
			//}
			nodes = append(nodes, config.NewNodeinfos...)
			shardid := maxShardId
			nodeid := -1
			for _, node := range nodes {
				nodeid++
				if params.IPmap_nodeTable[uint64(shardid)] == nil {
					params.IPmap_nodeTable[uint64(shardid)] = make(map[uint64]string)
				}
				params.IPmap_nodeTable[uint64(shardid)][uint64(nodeid)] = node.Ip + ":" + node.Port
			}
			fmt.Println("has generated new ipmap:")
			for i := 0; i < shardNum; i++ {
				for j := 0; j < nodeNum; j++ {
					fmt.Println("S" + strconv.Itoa(i) + "N" + strconv.Itoa(j) + ":" + params.IPmap_nodeTable[uint64(i)][uint64(j)])
				}
			}

			p.ip_nodeTable = params.IPmap_nodeTable

		}

	// handle the message from outside
	default:
		go p.ohm.HandleMessageOutsidePBFT(msgType, content)
	}
}

type DynamicConfig struct {
	OldNodeinfos []NodeInfo `json:"OldNodeinfos" binding:"required"`
	NewNodeinfos []NodeInfo `json:"NewNodeinfos" binding:"required"`
}

type NodeInfo struct {
	PublicKey string `json:"PublicKey" binding:"required"`
	Ip        string `json:"Ip" binding:"required"`
	Port      string `json:"Port" binding:"required"`
	ShardID   string `json:"ShardID" binding:"required"`
}

func (p *PbftConsensusNode) HandleClientRequest(con net.Conn) {
	defer con.Close()
	clientReader := bufio.NewReader(con)
	for {
		clientRequest, err := clientReader.ReadBytes('\n')
		if p.stopSignal.Load() {
			return
		}
		switch err {
		case nil:
			p.tcpPoolLock.Lock()
			p.handleMessage(clientRequest)
			p.tcpPoolLock.Unlock()
		case io.EOF:
			//log.Println("client closed the connection by terminating the process!!!")
			return
		default:
			log.Printf("error: %v\n", err)
			return
		}
	}
}
func (p *PbftConsensusNode) Beat(){

	for  {
		if p.stopSignal.Load() {
			return
		}
		if time.Since(p.lastbeattime).Seconds() >= 5{
			networks.TcpDial([]byte(""),"beat")
			p.lastbeattime = time.Now()
		}
		time.Sleep(100 * time.Millisecond)
	}

}
func (p *PbftConsensusNode) HandleClientRequest2() {
	for {
		if p.stopSignal.Load() {
			return
		}
		con := global.Conn
		clientReader := bufio.NewReader(con)
		for {
			if p.stopSignal.Load() {
				return
			}
			flag := true
			clientRequest, err := clientReader.ReadBytes('\n')
			if p.stopSignal.Load() {
				return
			}
			switch err {
			case nil:
				p.tcpPoolLock.Lock()
				p.handleMessage(clientRequest)
				p.tcpPoolLock.Unlock()
			case io.EOF:
				log.Println("client closed the connection by terminating the process...")
				flag = false
			default:
				//log.Printf("error: %v\n", err)
				flag = false
			}
			if !flag {
				break
			}
		}
		go con.Close()
		time.Sleep(500 * time.Millisecond)
	}

}
func getFreePort() (int, error) {
	rand.Seed(time.Now().UnixNano())
	for {
		p := 20000 + rand.Intn(40001) // 生成20000到60000之间的随机端口

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
// A consensus node starts tcp-listen.
func (p *PbftConsensusNode) TcpListen() {

	//if runtime.GOOS == "windows" {

	for  {
		freePort, _ := getFreePort()
		global.LocalPort = freePort
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(global.LocalPort))
		p.tcpln = ln
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for {
		conn, err := p.tcpln.Accept()
		if err != nil {
			return
		}
		go p.HandleClientRequest(conn)
	}
	return
	//}

	//addr := "0.0.0.0:" + strconv.Itoa(global.LocalPort)
	//
	//lc := net.ListenConfig{
	//	Control: func(network, address string, c syscall.RawConn) error {
	//		var opErr error
	//		err := c.Control(func(fd uintptr) {
	//			// 设置 SO_REUSEADDR
	//			opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	//		})
	//		if err != nil {
	//			return err
	//		}
	//		return opErr
	//	},
	//}
	//ln, err := lc.Listen(nil, "tcp", addr)
	//p.tcpln = ln
	//if err != nil {
	//	log.Panic(err)
	//}
	//for {
	//	conn, err := p.tcpln.Accept()
	//	if err != nil {
	//		return
	//	}
	//	go p.handleClientRequest(conn)
	//}

	//ln, err := net.Listen("tcp", p.RunningNode.IPaddr)

}

// When receiving a stop message, this node try to stop.
func (p *PbftConsensusNode) WaitToStop() {
	p.pl.Plog.Println("handling stop message")
	p.stopSignal.Store(true)
	networks.CloseAllConnInPool()
	p.tcpln.Close()
	p.closePbft()
	p.pl.Plog.Println("handled stop message in TCPListen Routine")
	p.pStop <- 1
}

// close the pbft
func (p *PbftConsensusNode) closePbft() {
	p.CurChain.CloseBlockChain()
}
