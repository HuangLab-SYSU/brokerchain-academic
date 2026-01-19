package pbft_all

import (
	"blockEmulator/core"
	"blockEmulator/global"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/shard"
	"blockEmulator/utils"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// this func is only invoked by main node
func (p *PbftConsensusNode) Propose() {
	// wait other nodes to start TCPlistening, sleep 5 sec.
	time.Sleep(5 * time.Second)

	nextRoundBeginSignal := make(chan bool)

	go func() {
		// go into the next round
		for {
			if p.stopSignal.Load() {
				return
			}
			time.Sleep(time.Duration(int64(p.pbftChainConfig.BlockInterval)) * time.Millisecond)
			if p.stopSignal.Load() {
				return
			}
			// send a signal to another GO-Routine. It will block until a GO-Routine try to fetch data from this channel.
			for p.pbftStage.Load() != 1 {
				time.Sleep(time.Millisecond * 100)
			}
			nextRoundBeginSignal <- true
		}
	}()

	go func() {
		// check whether to view change
		for {
			if p.stopSignal.Load() {
				return
			}
			time.Sleep(time.Second)
			if p.stopSignal.Load() {
				return
			}
			if time.Now().UnixMilli()-p.lastCommitTime.Load() > int64(params.PbftViewChangeTimeOut) {
				p.lastCommitTime.Store(time.Now().UnixMilli())
				if p.stopSignal.Load() {
					return
				}
				go p.viewChangePropose()
			}
		}
	}()

	go func() {
		// check whether to view change
		for {
			time.Sleep(time.Second)
			if time.Now().UnixMilli()-p.lastCommitTime2.Load() > int64(params.PbftStopShardTimeout) {
				go func() {
					defer func() {
						if err := recover(); err != nil {
							fmt.Println(err)
						}
					}()
					p.pStop <- 1
				}()
				go func() {
					defer func() {
						if err := recover(); err != nil {
							fmt.Println(err)
						}
					}()
					p.stopSignal.Store(true)
				}()
				go func() {
					defer func() {
						if err := recover(); err != nil {
							fmt.Println(err)
						}
					}()
					if global.Conn != nil {
						global.Conn.Close()
					}
				}()

				go func() {
					defer func() {
						if err := recover(); err != nil {
							fmt.Println(err)
						}
					}()
					if p.tcpln != nil {
						p.tcpln.Close()
					}
				}()
				go func() {
					defer func() {
						if err := recover(); err != nil {
							fmt.Println(err)
						}
					}()
					p.pbftLock.Lock()
					defer p.pbftLock.Unlock()
					p.conditionalVarpbftLock.Broadcast()
				}()

				go func() {
					defer func() {
						if err := recover(); err != nil {
							fmt.Println(err)
						}
					}()
					p.CurChain.Storage.DataBase.Close()
					p.CurChain.Triedb.CommitPreimages()
					p.CurChain.Db.Close()
				}()
				return
			}
		}
	}()

	for {
		select {
		case <-nextRoundBeginSignal:
			go func() {
				// if this node is not leader, do not propose.
				if uint64(p.view.Load()) != p.NodeID {
					return
				}

				p.sequenceLock.Lock()
				p.sequenceLockFlag.Store(true)
				//p.pl.Plog.Printf("S%dN%d get sequenceLock locked, now trying to propose...\n", p.ShardID, p.NodeID)
				//p.pl.Plog.Printf("S%d get sequenceLock locked, now trying to propose...\n", p.ShardID)
				// propose
				// implement interface to generate propose
				_, r := p.ihm.HandleinPropose()

				digest := getDigest(r)
				p.requestPool.Store(string(digest), r)
				//p.pl.Plog.Printf("S%dN%d put the request into the pool ...\n", p.ShardID, p.NodeID)
				//p.pl.Plog.Printf("S%d put the request into the pool ...\n", p.ShardID)

				ppmsg := message.PrePrepare{
					RequestMsg: r,
					Digest:     digest,
					SeqID:      p.sequenceID,
				}
				p.height2Digest[p.sequenceID] = string(digest)
				// marshal and broadcast
				ppbyte, err := json.Marshal(ppmsg)
				if err != nil {
					log.Panic()
				}
				msg_send := message.MergeMessage(message.CPrePrepare, ppbyte)
				if p.stopSignal.Load() {
					return
				}
				networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
				networks.TcpDial(msg_send, p.RunningNode.IPaddr)
				p.pbftStage.Store(2)
			}()

		case <-p.pStop:
			//p.pl.Plog.Printf("S%dN%d get stopSignal in Propose Routine, now stop...\n", p.ShardID, p.NodeID)
			//p.pl.Plog.Printf("S%d get stopSignal in Propose Routine, now stop...\n", p.ShardID)
			p.pl.Plog.Printf("Entering into a new shard...\n")
			return
		}
	}
}

// Handle pre-prepare messages here.
// If you want to do more operations in the pre-prepare stage, you can implement the interface "ExtraOpInConsensus",
// and call the function: **ExtraOpInConsensus.HandleinPrePrepare**
func (p *PbftConsensusNode) handlePrePrepare(content []byte) {
	//p.RunningNode.PrintNode()
	//fmt.Println("received the PrePrepare ...")
	// decode the message
	ppmsg := new(message.PrePrepare)
	err := json.Unmarshal(content, ppmsg)
	if err != nil {
		//log.Panic(err)
		fmt.Println(err)
		return
	}

	curView := p.view.Load()
	p.pbftLock.Lock()
	defer p.pbftLock.Unlock()
	for p.pbftStage.Load() < 1 && ppmsg.SeqID >= p.sequenceID && p.view.Load() == curView {
		p.conditionalVarpbftLock.Wait()
		if p.stopSignal.Load() {
			return
		}
	}
	defer p.conditionalVarpbftLock.Broadcast()

	// if this message is out of date, return.
	if ppmsg.SeqID < p.sequenceID || p.view.Load() != curView {
		return
	}
	if p.stopSignal.Load() {
		return
	}

	flag := false
	if digest := getDigest(ppmsg.RequestMsg); string(digest) != string(ppmsg.Digest) {
		//p.pl.Plog.Printf("S%dN%d : the digest is not consistent, so refuse to prepare. \n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : the digest is not consistent, so refuse to prepare. \n", p.ShardID)
	} else if p.sequenceID < ppmsg.SeqID {
		p.requestPool.Store(string(getDigest(ppmsg.RequestMsg)), ppmsg.RequestMsg)
		p.height2Digest[ppmsg.SeqID] = string(getDigest(ppmsg.RequestMsg))
		//p.askForLock.Lock()
		// request the block
		sn := &shard.Node{
			NodeID:  uint64(p.view.Load()),
			ShardID: p.ShardID,
			IPaddr:  p.ip_nodeTable[p.ShardID][uint64(p.view.Load())],
		}
		orequest := message.RequestOldMessage{
			SeqStartHeight: p.sequenceID + 1,
			SeqEndHeight:   ppmsg.SeqID,
			ServerNode:     sn,
			SenderNode:     p.RunningNode,
		}
		bromyte, err := json.Marshal(orequest)
		if err != nil {
			log.Panic()
		}

		//p.pl.Plog.Printf("S%dN%d : is now requesting message (seq %d to %d) ... \n", p.ShardID, p.NodeID, orequest.SeqStartHeight, orequest.SeqEndHeight)
		msg_send := message.MergeMessage(message.CRequestOldrequest, bromyte)
		networks.TcpDial(msg_send, orequest.ServerNode.IPaddr)
		//fmt.Println("ppmsg.SeqID:", ppmsg.SeqID)
		//p.pl.Plog.Printf("S%dN%d : the Sequence id is not consistent, so refuse to prepare. \n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : the Sequence id is not consistent, so refuse to prepare. \n", p.ShardID)
	} else {
		// do your operation in this interface
		flag = p.ihm.HandleinPrePrepare(ppmsg)
		p.requestPool.Store(string(getDigest(ppmsg.RequestMsg)), ppmsg.RequestMsg)
		p.height2Digest[ppmsg.SeqID] = string(getDigest(ppmsg.RequestMsg))
	}
	flag = true
	// if the message is true, broadcast the prepare message
	if flag {
		pre := message.Prepare{
			Digest:     ppmsg.Digest,
			SeqID:      ppmsg.SeqID,
			SenderNode: p.RunningNode,
		}
		prepareByte, err := json.Marshal(pre)
		if err != nil {
			log.Panic()
		}
		// broadcast
		msg_send := message.MergeMessage(message.CPrepare, prepareByte)
		if p.stopSignal.Load() {
			return
		}
		networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
		networks.TcpDial(msg_send, p.RunningNode.IPaddr)
		//p.pl.Plog.Printf("S%dN%d : has broadcast the prepare message \n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : has broadcast the prepare message \n", p.ShardID)

		// Pbft stage add 1. It means that this round of pbft goes into the next stage, i.e., Prepare stage.
		p.pbftStage.Add(1)
	}
}
func convertTo32ByteArray(input []byte) [32]byte {
	var result [32]byte
	copy(result[:], input)
	return result
}
func worker(wg *sync.WaitGroup, start, end int, problem string, blockhash [32]byte, difficulty int, resultChan chan<- int, flag *atomic.Bool, uid string) {
	defer wg.Done()
	s := problem
	previ := start
	for i := start; i < end; i++ {
		if i-previ > 10 {
			previ = i
			if flag.Load() {
				return
			}
		}
		sum256 := sha256.Sum256([]byte(s + uid + strconv.Itoa(i)))
		if check(sum256, blockhash, difficulty) {
			resultChan <- i
			return
		}
	}
}
func check(arr [32]byte, arr2 [32]byte, difficulty int) bool {
	count := 0
	for i := 0; i < 32 && count < difficulty; i++ {
		for j := 0; j < 8 && count < difficulty; j++ {
			if (arr[i] & (1 << (7 - j))) != (arr2[i] & (1 << (7 - j))) {
				return false
			} else {
				count++
			}
		}
	}
	return true
}

// Handle prepare messages here.
// If you want to do more operations in the prepare stage, you can implement the interface "ExtraOpInConsensus",
// and call the function: **ExtraOpInConsensus.HandleinPrepare**
func (p *PbftConsensusNode) handlePrepare(content []byte) {
	// decode the message
	pmsg := new(message.Prepare)
	err := json.Unmarshal(content, pmsg)
	if err != nil {
		//log.Panic(err)
		fmt.Println(err)
		return
	}
	//p.pl.Plog.Printf("S%dN%d : received the Prepare from N%d...\n", p.ShardID, p.NodeID,pmsg.SenderNode.NodeID)
	//p.pl.Plog.Printf("S%d : received the Prepare from N%d...\n", p.ShardID, pmsg.SenderNode.NodeID)

	curView := p.view.Load()
	p.pbftLock.Lock()
	defer p.pbftLock.Unlock()
	for p.pbftStage.Load() < 2 && pmsg.SeqID >= p.sequenceID && p.view.Load() == curView {
		p.conditionalVarpbftLock.Wait()
		if p.stopSignal.Load() {
			return
		}
	}
	defer p.conditionalVarpbftLock.Broadcast()
	if p.stopSignal.Load() {
		return
	}
	// if this message is out of date, return.
	if pmsg.SeqID < p.sequenceID || p.view.Load() != curView {
		return
	}

	if _, ok := p.requestPool.Load(string(pmsg.Digest)); !ok {
		//p.pl.Plog.Printf("S%dN%d : doesn't have the digest in the requst pool, refuse to commit\n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : doesn't have the digest in the requst pool, refuse to commit\n", p.ShardID)
		return
	} else if p.sequenceID < pmsg.SeqID {
		//p.pl.Plog.Printf("S%dN%d : inconsistent sequence ID, refuse to commit\n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : inconsistent sequence ID, refuse to commit\n", p.ShardID, )
		//p.askForLock.Lock()
		// request the block
		sn := &shard.Node{
			NodeID:  uint64(p.view.Load()),
			ShardID: p.ShardID,
			IPaddr:  p.ip_nodeTable[p.ShardID][uint64(p.view.Load())],
		}
		orequest := message.RequestOldMessage{
			SeqStartHeight: p.sequenceID + 1,
			SeqEndHeight:   pmsg.SeqID,
			ServerNode:     sn,
			SenderNode:     p.RunningNode,
		}
		bromyte, err := json.Marshal(orequest)
		if err != nil {
			log.Panic()
		}

		//p.pl.Plog.Printf("S%dN%d : is now requesting message (seq %d to %d) ... \n", p.ShardID, p.NodeID, orequest.SeqStartHeight, orequest.SeqEndHeight)
		msg_send := message.MergeMessage(message.CRequestOldrequest, bromyte)
		networks.TcpDial(msg_send, orequest.ServerNode.IPaddr)
	}
	//else {
	// if needed more operations, implement interfaces
	//p.ihm.HandleinPrepare(pmsg)

	p.set2DMap(true, string(pmsg.Digest), pmsg.SenderNode)
	cnt := len(p.cntPrepareConfirm[string(pmsg.Digest)])

	// if the node has received 2f messages (itself included), and it haven't committed, then it commit
	p.lock.Lock()
	defer p.lock.Unlock()
	if uint64(cnt) >= 2*p.malicious_nums+1 && !p.isCommitBordcast[string(pmsg.Digest)] {
		//p.pl.Plog.Printf("S%dN%d : is going to commit\n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : is going to commit\n", p.ShardID)

		request0, _ := p.requestPool.Load(string(pmsg.Digest))
		request := request0.(*message.Request)
		answer := ""
		if request.RequestType != message.PartitionReq {

			block := core.DecodeB(request.Msg.Content)

			if !global.Senior.Load() {
				for {
					answer1 := ""
					uid := uuid.New().String()
					resultChan := make(chan int, 1)
					doneChan := make(chan bool, 1)
					var wg sync.WaitGroup
					maxRange := 1000000000
					workers := runtime.NumCPU()

					problem := string(block.Hash)
					blockhash_ := block.Hash
					blockhash := convertTo32ByteArray(blockhash_)
					if workers > 16 {
						workers = 16
					}
					if workers < 1 {
						workers = 1
					}
					//workers = 1
					wg.Add(workers)
					perWorker := maxRange / workers
					flag := atomic.Bool{}
					for i := 0; i < workers; i++ {
						start := i * perWorker
						end := (i + 1) * perWorker
						if i == workers-1 {
							end = maxRange
						}
						if global.Senior.Load() {
							go worker(&wg, start, end, problem, blockhash, 2, resultChan, &flag, uid)
						} else {
							go worker(&wg, start, end, problem, blockhash, 22, resultChan, &flag, uid)
						}
					}

					go func() {
						wg.Wait()
						doneChan <- true
						flag.Store(true)
					}()
					select {
					case i := <-resultChan:
						flag.Store(true)
						answer1 = strconv.Itoa(i)
						break
					case <-doneChan:
						//fmt.Printf("No solution found in range %d\n", maxRange)
					}
					if answer1 != "" {
						answer = uid + answer1
						//fmt.Println("answer is: " + answer)
						break
					}
				}
			}

		}
		// generate commit and broadcast
		c := message.Commit{
			Digest:     pmsg.Digest,
			SeqID:      pmsg.SeqID,
			SenderNode: p.RunningNode,
			Answer:     answer,
		}
		commitByte, err := json.Marshal(c)
		if err != nil {
			log.Panic()
		}
		msg_send := message.MergeMessage(message.CCommit, commitByte)
		if p.stopSignal.Load() {
			return
		}
		networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
		networks.TcpDial(msg_send, p.RunningNode.IPaddr)
		p.isCommitBordcast[string(pmsg.Digest)] = true
		//p.pl.Plog.Printf("S%dN%d : commit is broadcast\n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : commit is broadcast\n", p.ShardID)

		p.pbftStage.Add(1)
	}
	//}
}

// Handle commit messages here.
// If you want to do more operations in the commit stage, you can implement the interface "ExtraOpInConsensus",
// and call the function: **ExtraOpInConsensus.HandleinCommit**
func (p *PbftConsensusNode) handleCommit(content []byte) {
	// decode the message
	cmsg := new(message.Commit)
	err := json.Unmarshal(content, cmsg)
	if err != nil {
		//log.Panic(err)
		fmt.Println(err)
		return
	}
	//p.pl.Plog.Printf("S%dN%d received the Commit from ...%d\n", p.ShardID, p.NodeID, cmsg.SenderNode.NodeID)
	//p.pl.Plog.Printf("S%d received the Commit from ...%d\n", p.ShardID, cmsg.SenderNode.NodeID)

	curView := p.view.Load()
	p.pbftLock.Lock()
	defer p.pbftLock.Unlock()
	for p.pbftStage.Load() < 3 && cmsg.SeqID >= p.sequenceID && p.view.Load() == curView {
		p.conditionalVarpbftLock.Wait()
		if p.stopSignal.Load() {
			return
		}
	}
	defer p.conditionalVarpbftLock.Broadcast()
	if p.stopSignal.Load() {
		return
	}
	if cmsg.SeqID < p.sequenceID || p.view.Load() != curView {
		return
	}

	p.set2DMap2(string(cmsg.Digest), cmsg.SenderNode, cmsg.Answer)
	//p.set2DMap(false,string(cmsg.Digest), cmsg.SenderNode)

	cnt := len(p.cntCommitConfirm[string(cmsg.Digest)])

	if p.stopSignal.Load() {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()

	if uint64(cnt) >= 2*p.malicious_nums+1 && !p.isReply[string(cmsg.Digest)] {
		//p.pl.Plog.Printf("S%dN%d : has received 2f + 1 commits ... \n", p.ShardID, p.NodeID)
		//p.pl.Plog.Printf("S%d : has received 2f + 1 commits ... \n", p.ShardID)
		// if this node is left behind, so it need to requst blocks
		if _, ok := p.requestPool.Load(string(cmsg.Digest)); !ok {
			p.isReply[string(cmsg.Digest)] = true
			//p.askForLock.Lock()
			// request the block
			sn := &shard.Node{
				NodeID:  uint64(p.view.Load()),
				ShardID: p.ShardID,
				IPaddr:  p.ip_nodeTable[p.ShardID][uint64(p.view.Load())],
			}
			orequest := message.RequestOldMessage{
				SeqStartHeight: p.sequenceID + 1,
				SeqEndHeight:   cmsg.SeqID,
				ServerNode:     sn,
				SenderNode:     p.RunningNode,
			}
			bromyte, err := json.Marshal(orequest)
			if err != nil {
				log.Panic()
			}

			//p.pl.Plog.Printf("S%dN%d : is now requesting message (seq %d to %d) ... \n", p.ShardID, p.NodeID, orequest.SeqStartHeight, orequest.SeqEndHeight)
			msg_send := message.MergeMessage(message.CRequestOldrequest, bromyte)
			networks.TcpDial(msg_send, orequest.ServerNode.IPaddr)
		} else {
			if p.stopSignal.Load() {
				return
			}
			// implement interface
			p.ihm.HandleinCommit(cmsg)

			if uint64(p.view.Load()) == p.NodeID {
				request0, _ := p.requestPool.Load(string(cmsg.Digest))
				request := request0.(*message.Request)
				m3 := make([]string, 0)
				m4 := make([]string, 0)
				//m2 := p.cntCommitConfirm[string(cmsg.Digest)]
				//for k, v := range m2 {
				//	if v {
				//		s1 := strconv.Itoa(int(k.ShardID)) + ":" + strconv.Itoa(int(k.NodeID))
				//		m3 = append(m3, s1)
				//	}
				//}
				if request.RequestType != message.PartitionReq {

					block1 := core.DecodeB(request.Msg.Content)
					m2 := p.cntCommitConfirm[string(cmsg.Digest)]

					if global.Senior.Load() {
						for k, v := range m2 {
							s1 := strconv.Itoa(int(k.ShardID)) + ":" + strconv.Itoa(int(k.NodeID))
							m3 = append(m3, s1)
							m4 = append(m4, v)
						}
					} else {
						for k, v := range m2 {
							if len(v) != 0 && v != "" {
								s_ := string(block1.Hash) + v
								arr1 := sha256.Sum256([]byte(s_))
								arr2 := convertTo32ByteArray(block1.Hash)
								diff := 22
								if check(arr1, arr2, diff) {
									//fmt.Println("验证成功："+v)
									s1 := strconv.Itoa(int(k.ShardID)) + ":" + strconv.Itoa(int(k.NodeID))
									m3 = append(m3, s1)
									m4 = append(m4, v)
								}
							}
						}
					}

				}
				root := hex.EncodeToString(p.CurChain.CurrentBlock.Header.StateRoot)
				uid := uuid.New().String()

				r0, _ := p.requestPool.Load(string(cmsg.Digest))
				r := r0.(*message.Request)
				if r.RequestType != message.PartitionReq {
					block := core.DecodeB(r.Msg.Content)
					thedata := uid + root
					if uint64(p.view.Load()) == p.NodeID {
						thedata = thedata + "true"
					} else {
						thedata = thedata + "false"
					}
					sign1, sign2, _ := utils.SignECDSA(global.PrivateKeyBigInt, thedata)
					report := ReportBlockReq{
						PublicKey:    global.PublicKey,
						RandomStr:    uid,
						Sign1:        sign1,
						Sign2:        sign2,
						Root:         root,
						Signs:        m3,
						Signs2:       m4,
						BlockHash:    block.Hash,
						PreBlockHash: block.Header.ParentBlockHash,
						ShardId:      p.ShardID,
					}
					if block.Body != nil && len(block.Body) > 0 {
						report.Txs = block.Body
					}
					if uint64(p.view.Load()) == p.NodeID {
						report.IsLeader = "true"
					} else {
						report.IsLeader = "false"
					}
					m, _ := json.Marshal(report)
					url := "reportblock"
					if global.Senior.Load() {
						url = "reportblock_senior"
					}
					go Post(url, m)
				}
			}
			p.isReply[string(cmsg.Digest)] = true
			//p.pl.Plog.Printf("S%dN%d: The #%d round of PBFT consensus has concluded \n", p.ShardID, p.NodeID, p.sequenceID)
			p.pl.Plog.Printf("S%d: The #%d round of PBFT consensus has concluded \n", p.ShardID, p.sequenceID)
			p.sequenceID += 1
			p.lastCommitTime2.Store(time.Now().UnixMilli())
		}

		p.pbftStage.Store(1)
		p.lastCommitTime.Store(time.Now().UnixMilli())

		// if this node is a main node, then unlock the sequencelock
		//if p.NodeID == uint64(p.view.Load()) && p.sequenceLockFlag.Load(){
		if p.NodeID == uint64(p.view.Load()) && p.sequenceLockFlag.Load() {
			p.sequenceLock.Unlock()
			p.sequenceLockFlag.Store(false)
			//p.pl.Plog.Printf("S%dN%d get sequenceLock unlocked...\n", p.ShardID, p.NodeID)
			//p.pl.Plog.Printf("S%d get sequenceLock unlocked...\n", p.ShardID)
		}
	}
}

func Post(url string, data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", "http://"+global.ServerHost+":"+global.ServerPort+"/"+url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println("Error sending request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}
	return body, nil
}
func GetRandStrSign() (string, [32]byte) {
	uid := uuid.New().String()
	s := uid + global.PrivateKey
	sum256 := sha256.Sum256([]byte(s))
	return uid, sum256
}

type ReportBlockReq struct {
	PublicKey    string              `json:"PublicKey" binding:"required"`
	RandomStr    string              `json:"RandomStr" binding:"required"`
	Sign1        string              `json:"Sign1" binding:"required"`
	Sign2        string              `json:"Sign2" binding:"required"`
	IsLeader     string              `json:"IsLeader" binding:"required"`
	Root         string              `json:"Root" binding:"required"`
	Signs        []string            `json:"Signs" binding:"required"`
	Signs2       []string            `json:"Signs2" `
	BlockHash    []byte              `json:"BlockHash" `
	PreBlockHash []byte              `json:"PreBlockHash" `
	Txs          []*core.Transaction `json:"Txs"`
	ShardId      uint64              `json:"ShardId" binding:"required"`
}

// this func is only invoked by the main node,
// if the request is correct, the main node will send
// block back to the message sender.
// now this function can send both block and partition
func (p *PbftConsensusNode) handleRequestOldSeq(content []byte) {
	if uint64(p.view.Load()) != p.NodeID {
		return
	}

	rom := new(message.RequestOldMessage)
	err := json.Unmarshal(content, rom)
	if err != nil {
		log.Panic()
	}
	p.pl.Plog.Printf("S%dN%d : received the old message requst from ...", p.ShardID, p.NodeID)
	rom.SenderNode.PrintNode()

	oldR := make([]*message.Request, 0)
	for height := rom.SeqStartHeight; height <= rom.SeqEndHeight; height++ {
		if _, ok := p.height2Digest[height]; !ok {
			p.pl.Plog.Printf("S%dN%d : has no this digest to this height %d\n", p.ShardID, p.NodeID, height)
			break
		}
		if r0, ok := p.requestPool.Load(p.height2Digest[height]); !ok {
			p.pl.Plog.Printf("S%dN%d : has no this message to this digest %d\n", p.ShardID, p.NodeID, height)
			break
		} else {
			r := (r0).(*message.Request)
			oldR = append(oldR, r)
		}
	}
	p.pl.Plog.Printf("S%dN%d : has generated the message to be sent\n", p.ShardID, p.NodeID)
	if p.stopSignal.Load() {
		return
	}
	p.ihm.HandleReqestforOldSeq(rom)

	// send the block back
	sb := message.SendOldMessage{
		SeqStartHeight: rom.SeqStartHeight,
		SeqEndHeight:   rom.SeqEndHeight,
		OldRequest:     oldR,
		SenderNode:     p.RunningNode,
	}
	sbByte, err := json.Marshal(sb)
	if err != nil {
		log.Panic()
	}
	msg_send := message.MergeMessage(message.CSendOldrequest, sbByte)
	if p.stopSignal.Load() {
		return
	}
	networks.TcpDial(msg_send, rom.SenderNode.IPaddr)
	p.pl.Plog.Printf("S%dN%d : send blocks\n", p.ShardID, p.NodeID)
}

// node requst blocks and receive blocks from the main node
func (p *PbftConsensusNode) handleSendOldSeq(content []byte) {
	som := new(message.SendOldMessage)
	err := json.Unmarshal(content, som)
	if err != nil {
		log.Panic()
	}
	p.pl.Plog.Printf("S%d : has received the SendOldMessage message\n", p.ShardID)

	// implement interface for new consensus
	p.ihm.HandleforSequentialRequest(som)
	beginSeq := som.SeqStartHeight
	for idx, r := range som.OldRequest {
		p.requestPool.Store(string(getDigest(r)), r)
		p.height2Digest[uint64(idx)+beginSeq] = string(getDigest(r))
		p.isReply[string(getDigest(r))] = true
		p.pl.Plog.Printf("this round of pbft %d is end \n", uint64(idx)+beginSeq)
	}
	p.sequenceID = som.SeqEndHeight + 1
	if rDigest, ok1 := p.height2Digest[p.sequenceID]; ok1 {
		if r1, ok2 := p.requestPool.Load(rDigest); ok2 {
			r := r1.(*message.Request)
			ppmsg := &message.PrePrepare{
				RequestMsg: r,
				SeqID:      p.sequenceID,
				Digest:     getDigest(r),
			}
			flag := false
			flag = p.ihm.HandleinPrePrepare(ppmsg)
			if flag {
				pre := message.Prepare{
					Digest:     ppmsg.Digest,
					SeqID:      ppmsg.SeqID,
					SenderNode: p.RunningNode,
				}
				prepareByte, err := json.Marshal(pre)
				if err != nil {
					log.Panic()
				}
				// broadcast
				msg_send := message.MergeMessage(message.CPrepare, prepareByte)
				if p.stopSignal.Load() {
					return
				}
				networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
				//p.pl.Plog.Printf("S%dN%d : has broadcast the prepare message \n", p.ShardID, p.NodeID)
				p.pl.Plog.Printf("S%d : has broadcast the prepare message \n", p.ShardID)
			}
		}
	}

	//p.askForLock.Unlock()
}
