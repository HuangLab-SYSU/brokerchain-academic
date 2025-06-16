package message

import (
	"blockEmulator/core"
	"bytes"
	"encoding/gob"
	"log"
)

var (
	AccountState_and_TX MessageType = "AccountState&txs"
	PartitionReq        RequestType = "PartitionReq"
	CPartitionMsg       MessageType = "PartitionModifiedMap"
	CPartitionReady     MessageType = "ready for partition"
)

type M struct {
	Infos []AccInfo
}

func (atm *M) Encode() []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(atm)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}
func (as *AccInfo) Encode() []byte {
	var buff bytes.Buffer
	encoder := gob.NewEncoder(&buff)
	err := encoder.Encode(as)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}
type AccInfo struct {
	Addr string
	ShardId uint64
	Balance string
}

type PartitionModifiedMap struct {
	PartitionModified map[string]uint64
}

type AccountTransferMsg struct {
	ModifiedMap  map[string]uint64
	Addrs        []string
	AccountState []*core.AccountState
	ATid         uint64
}

type PartitionReady struct {
	FromShard uint64
	NowSeqID  uint64
}

// this message used in inter-shard, it will be sent between leaders.
type AccountStateAndTx struct {
	Addrs        []string
	AccountState []*core.AccountState
	Txs          []*core.Transaction
	FromShard    uint64
}

func (atm *AccountTransferMsg) Encode() []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(atm)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}

func DecodeAccountTransferMsg(content []byte) *AccountTransferMsg {
	var atm AccountTransferMsg

	decoder := gob.NewDecoder(bytes.NewReader(content))
	err := decoder.Decode(&atm)
	if err != nil {
		log.Panic(err)
	}

	return &atm
}

func DecodeMsg(content []byte) *M {
	var atm M

	decoder := gob.NewDecoder(bytes.NewReader(content))
	err := decoder.Decode(&atm)
	if err != nil {
		log.Panic(err)
	}

	return &atm
}