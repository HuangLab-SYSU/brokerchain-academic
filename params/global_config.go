package params

var (
	// The following parameters can be set in main.go.
	// default values:
	NodesInShard = 4 // \# of Nodes in a shard.
	ShardNum     = 4 // \# of shards.
)

// consensus layer & output file path
var (
	ConsensusMethod = 1 // ConsensusMethod an Integer, which indicates the choice ID of methods / consensuses. Value range: [0, 4), representing [CLPA_Broker, CLPA, Broker, Relay]"

	PbftViewChangeTimeOut = 300000 // The view change threshold of pbft. If the process of PBFT is too slow, the view change mechanism will be triggered.
	PbftStopShardTimeout = 3300000
	Block_Interval = 5000 // The time interval for generating a new block

	MaxBlockSize_global = 2000  // The maximum number of transactions a block contains
	BlocksizeInBytes    = 20000 // The maximum size (in bytes) of block body
	UseBlocksizeInBytes = 0     // Use blocksizeInBytes as the blocksize measurement if '1'.

	InjectSpeed   = 2000   // The speed of transaction injection
	TotalDataSize = 160000 // The total number of txs to be injected
	TxBatchSize   = 16000  // The supervisor read a batch of txs then send them. The size of a batch is 'TxBatchSize'

	BrokerNum            = 10 // The # of Broker accounts used in Broker / CLPA_Broker.
	RelayWithMerkleProof = 0  // When using a consensus about "Relay", nodes will send Tx Relay with proof if "RelayWithMerkleProof" = 1

	ExpDataRootDir     = "expTest"                     // The root dir where the experimental data should locate.
	DataWrite_path     = ExpDataRootDir + "/result/"   // Measurement data result output path
	LogWrite_path      = ExpDataRootDir + "/log"       // Log output path
	DatabaseWrite_path = ExpDataRootDir + "/database/" // database write path

	SupervisorAddr = "127.0.0.1:18800"        // Supervisor ip address
	DatasetFile    = `./selectedTxs_300K.csv` // The raw BlockTransaction data path

	ReconfigTimeGap = 50 // The time gap between epochs. This variable is only used in CLPA / CLPA_Broker now.
)

// network layer
var (
	Delay       int // The delay of network (ms) when sending. 0 if delay < 0
	JitterRange int // The jitter range of delay (ms). Jitter follows a uniform distribution. 0 if JitterRange < 0.
	Bandwidth   int // The bandwidth limit (Bytes). +inf if bandwidth < 0
)

// read from file
type globalConfig struct {
	ConsensusMethod int `json:"ConsensusMethod"`

	PbftViewChangeTimeOut int `json:"PbftViewChangeTimeOut"`

	ExpDataRootDir string `json:"ExpDataRootDir"`

	BlockInterval int `json:"Block_Interval"`

	BlocksizeInBytes    int `json:"BlocksizeInBytes"`
	MaxBlockSizeGlobal  int `json:"BlockSize"`
	UseBlocksizeInBytes int `json:"UseBlocksizeInBytes"`

	InjectSpeed   int `json:"InjectSpeed"`
	TotalDataSize int `json:"TotalDataSize"`

	TxBatchSize          int    `json:"TxBatchSize"`
	BrokerNum            int    `json:"BrokerNum"`
	RelayWithMerkleProof int    `json:"RelayWithMerkleProof"`
	DatasetFile          string `json:"DatasetFile"`
	ReconfigTimeGap      int    `json:"ReconfigTimeGap"`

	Delay       int `json:"Delay"`
	JitterRange int `json:"JitterRange"`
	Bandwidth   int `json:"Bandwidth"`
}

func ReadConfigFile() {

	ConsensusMethod = 1

	PbftViewChangeTimeOut = 300000
	PbftStopShardTimeout = 3300000
	// data file params
	ExpDataRootDir = "expTest"
	DataWrite_path = ExpDataRootDir + "/result/"
	LogWrite_path = ExpDataRootDir + "/log"
	DatabaseWrite_path = ExpDataRootDir + "/database/"

	Block_Interval = 10000

	MaxBlockSize_global = 2000
	BlocksizeInBytes = 200000
	UseBlocksizeInBytes = 0

	InjectSpeed = 2000
	TotalDataSize = 160000
	TxBatchSize = 16000

	BrokerNum = 50
	RelayWithMerkleProof = 0
	DatasetFile = "./selectedTxs_300K.csv"

	ReconfigTimeGap = 50

	// network params
	Delay = -1
	JitterRange = -1
	Bandwidth = 100000000
}
