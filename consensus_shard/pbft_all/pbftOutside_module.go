package pbft_all

import (
	"blockEmulator/chain"
	"blockEmulator/message"
	"encoding/json"
	"log"
)

// This module used in the blockChain using transaction relaying mechanism.
// "Raw" means that the pbft only make block consensus.
type RawRelayOutsideModule struct {
	pbftNode *PbftConsensusNode
}

// msgType canbe defined in message
func (rrom *RawRelayOutsideModule) HandleMessageOutsidePBFT(msgType message.MessageType, content []byte) bool {
	switch msgType {
	case message.CRelay:
		rrom.handleRelay(content)
	case message.CRelayWithProof:
		rrom.handleRelayWithProof(content)
	case message.CInject:
		rrom.handleInjectTx(content)
	//case message.CReconfig:
	//	it := new(M)
	//	err := json.Unmarshal(content, it)
	//
	//	if err == nil {
	//		rrom.pbftNode.sequenceLock.Lock()
	//		defer rrom.pbftNode.sequenceLock.Unlock()
	//		st, _ := trie.New(trie.TrieID(common.BytesToHash(rrom.pbftNode.CurChain.CurrentBlock.Header.StateRoot)), rrom.pbftNode.CurChain.Triedb)
	//		infos := it.Infos
	//		for _, info := range infos {
	//			addr := info.Addr
	//			if info.ShardId != rrom.pbftNode.ShardID{
	//				s_state_enc, _ := st.Get([]byte(addr))
	//				if s_state_enc != nil {
	//					st.Delete([]byte(addr))
	//				}
	//			}else {
	//				var s_state core.AccountState
	//				s_state.AcAddress = addr
	//				bigint:=new(big.Int)
	//				bigint.SetString(info.Balance,10)
	//				s_state.Balance = bigint
	//				st.Update([]byte(addr),s_state.Encode())
	//			}
	//		}
	//		rt, ns := st.Commit(false)
	//		// if `ns` is nil, the `err = bc.Triedb.Update(trie.NewWithNodeSet(ns))` will report an error.
	//		if ns != nil {
	//			err = rrom.pbftNode.CurChain.Triedb.Update(trie.NewWithNodeSet(ns))
	//			if err != nil {
	//				fmt.Println(err)
	//			}
	//			err = rrom.pbftNode.CurChain.Triedb.Commit(rt, false)
	//			if err != nil {
	//				fmt.Println(err)
	//			}
	//		}
	//		bh := &core.BlockHeader{
	//			ParentBlockHash: rrom.pbftNode.CurChain.CurrentBlock.Hash,
	//			Number:          rrom.pbftNode.CurChain.CurrentBlock.Header.Number + 1,
	//			Time:            time.Now(),
	//		}
	//		bh.StateRoot = rt.Bytes()
	//		b := core.NewBlock2(bh)
	//		b.Hash = b.Header.Hash()
	//		rrom.pbftNode.CurChain.AddBlock(b)

		//}
	default:
	}
	return true
}

// receive relay transaction, which is for cross shard txs
func (rrom *RawRelayOutsideModule) handleRelay(content []byte) {
	relay := new(message.Relay)
	err := json.Unmarshal(content, relay)
	if err != nil {
		log.Panic(err)
	}
	rrom.pbftNode.pl.Plog.Printf("S%dN%d : has received relay txs from shard %d, the senderSeq is %d\n", rrom.pbftNode.ShardID, rrom.pbftNode.NodeID, relay.SenderShardID, relay.SenderSeq)
	rrom.pbftNode.CurChain.Txpool.AddTxs2Pool(relay.Txs)
	rrom.pbftNode.seqMapLock.Lock()
	rrom.pbftNode.seqIDMap[relay.SenderShardID] = relay.SenderSeq
	rrom.pbftNode.seqMapLock.Unlock()
	rrom.pbftNode.pl.Plog.Printf("S%dN%d : has handled relay txs msg\n", rrom.pbftNode.ShardID, rrom.pbftNode.NodeID)
}

func (rrom *RawRelayOutsideModule) handleRelayWithProof(content []byte) {
	rwp := new(message.RelayWithProof)
	err := json.Unmarshal(content, rwp)
	if err != nil {
		log.Panic(err)
	}
	rrom.pbftNode.pl.Plog.Printf("S%dN%d : has received relay txs & proofs from shard %d, the senderSeq is %d\n", rrom.pbftNode.ShardID, rrom.pbftNode.NodeID, rwp.SenderShardID, rwp.SenderSeq)
	// validate the proofs of txs
	isAllCorrect := true
	for i, tx := range rwp.Txs {
		if ok, _ := chain.TxProofVerify(tx.TxHash, &rwp.TxProofs[i]); !ok {
			isAllCorrect = false
			break
		}
	}
	if isAllCorrect {
		rrom.pbftNode.pl.Plog.Println("All proofs are passed.")
		rrom.pbftNode.CurChain.Txpool.AddTxs2Pool(rwp.Txs)
	} else {
		rrom.pbftNode.pl.Plog.Println("Err: wrong proof!")
	}

	rrom.pbftNode.seqMapLock.Lock()
	rrom.pbftNode.seqIDMap[rwp.SenderShardID] = rwp.SenderSeq
	rrom.pbftNode.seqMapLock.Unlock()
	rrom.pbftNode.pl.Plog.Printf("S%dN%d : has handled relay txs msg\n", rrom.pbftNode.ShardID, rrom.pbftNode.NodeID)
}

func (rrom *RawRelayOutsideModule) handleInjectTx(content []byte) {
	it := new(message.InjectTxs)
	err := json.Unmarshal(content, it)
	if err != nil {
		log.Panic(err)
	}
	rrom.pbftNode.CurChain.Txpool.AddTxs2Pool(it.Txs)
	rrom.pbftNode.pl.Plog.Printf("S%dN%d : has handled injected txs msg, txs: %d \n", rrom.pbftNode.ShardID, rrom.pbftNode.NodeID, len(it.Txs))
}
