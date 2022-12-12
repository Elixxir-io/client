package gateway

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/stoppable"
	"gitlab.com/elixxir/client/v4/storage"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/ndf"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
)

type hostPool struct {
	/*internal state*/
	writePool *pool
	readPool  atomic.Value

	ndfMap map[id.ID]int // Map gateway ID to its index in the NDF
	ndf    *ndf.NetworkDefinition

	/*Runner inputs*/
	// a send on this channel adds a node to the host pool
	// if a nil id is sent, a few random nodes are tested
	// and the best is added
	// if a specific id is sent, that id is added
	addRequest    chan *id.ID
	removeRequest chan *id.ID
	newHost       chan *connect.Host
	doneTesting   chan []*connect.Host
	newNdf        chan *ndf.NetworkDefinition

	/*worker inputs*/
	// tests the list of nodes. Finds the one with the lowest ping,
	// connects, and then returns over addNode
	testNodes chan []*connect.Host

	/* external objects*/
	rng       *fastRNG.StreamGenerator
	params    Params
	manager   HostManager
	filterMux sync.Mutex
	filter    Filter
	kv        *versioned.KV

	/* computed parameters*/
	numNodesToTest int
}

// HostManager Interface allowing storage and retrieval of Host objects
type HostManager interface {
	GetHost(hostId *id.ID) (*connect.Host, bool)
	AddHost(hid *id.ID, address string, cert []byte, params connect.HostParams) (
		host *connect.Host, err error)
	RemoveHost(hid *id.ID)
}

// Filter filters out IDs from the provided map based on criteria in the NDF.
// The passed in map is a map of the NDF for easier access.  The map is
// ID -> index in the NDF. There is no multithreading; the filter function can
// either edit the passed map or make a new one and return it. The general
// pattern is to loop through the map, then look up data about the nodes in the
// NDF to make a filtering decision, then add them to a new map if they are
// accepted.
type Filter func(map[id.ID]int, *ndf.NetworkDefinition) map[id.ID]int

var defaultFilter = func(m map[id.ID]int, _ *ndf.NetworkDefinition) map[id.ID]int {
	return m
}

func newHostPool(params Params, rng *fastRNG.StreamGenerator,
	netDef *ndf.NetworkDefinition, getter HostManager,
	storage storage.Session) (*hostPool, error) {
	var err error

	// Determine size of HostPool
	if params.PoolSize == 0 {
		params.PoolSize, err = getPoolSize(
			uint32(len(netDef.Gateways)), params.MaxPoolSize)
		if err != nil {
			return nil, err
		}
	}

	//calculate the minimum input of buffers
	buffLen := 10 * len(netDef.Gateways)
	if buffLen < int(params.MinBufferLength) {
		buffLen = int(params.MinBufferLength)
	}

	// override rotation and tune parameters if the network is
	// too small
	if int(params.PoolSize*params.MaxPings) > len(netDef.Gateways) {
		params.EnableRotation = false
		params.MaxPings = 1
	}

	//build the underlying pool
	p := newPool(int(params.PoolSize))

	//build the host pool
	hp := &hostPool{
		writePool:     p,
		readPool:      atomic.Value{},
		ndf:           netDef.DeepCopy(),
		addRequest:    make(chan *id.ID, buffLen),
		removeRequest: make(chan *id.ID, buffLen),
		newHost:       make(chan *connect.Host, buffLen),
		doneTesting:   make(chan []*connect.Host, buffLen),
		newNdf:        make(chan *ndf.NetworkDefinition, buffLen),
		testNodes:     make(chan []*connect.Host, buffLen),
		rng:           rng,
		params:        params,
		manager:       getter,
		filter:        defaultFilter,
		kv:            storage.GetKV().Prefix(hostListPrefix),
		numNodesToTest: getNumNodesToTest(int(params.MaxPings),
			len(netDef.Gateways), int(params.PoolSize)),
	}

	hp.readPool.Store(p.deepCopy())

	//process the ndf
	hp.ndfMap = hp.processNdf(hp.ndf)

	//prime the host pool at add its first hosts
	hl, err := getHostPreparedList(hp.kv, int(params.PoolSize))
	if err != nil {
		jww.WARN.Printf("Starting host pool from scratch, "+
			"cannot get old pool: %+v", err)
	}
	for i := range hl {
		hp.addRequest <- hl[i]
	}

	return hp, nil
}

// StartProcesses starts all background threads fgr the host pool
func (hp *hostPool) StartProcesses() stoppable.Stoppable {
	multi := stoppable.NewMulti("HostPool")

	// Create the Node Tester workers
	for i := 0; i < hp.params.NumConnectionsWorkers; i++ {
		stop := stoppable.NewSingle(
			"Node Tester Worker " + strconv.Itoa(int(i)))
		go hp.nodeTester(stop)
		multi.Add(stop)
	}

	//if rotation is enabled, start the rotation thread
	if hp.params.EnableRotation {
		rotationStop := stoppable.NewSingle("Rotation")
		go hp.Rotation(rotationStop)
		multi.Add(rotationStop)
	}

	//start the main thread
	runnerStop := stoppable.NewSingle("Runner")
	go hp.runner(runnerStop)
	multi.Add(runnerStop)

	return multi
}

// Remove triggers the node to be removed from the host pool and disconnects,
// if the node is present
func (hp *hostPool) Remove(h *connect.Host) {
	h.Disconnect()
	select {
	case hp.removeRequest <- h.GetId():
	default:
		jww.WARN.Printf("Failed to pass instruction to remove %s", h.GetId())
	}
}

// Add adds the given gateway to the hostpool, if it is present
func (hp *hostPool) Add(gwId *id.ID) {
	select {
	case hp.addRequest <- gwId:
	default:
		jww.WARN.Printf("Failed to pass instruction to add %s", gwId)
	}
}

// UpdateNdf updates the NDF used by the hostpool,
// updating hosts and removing gateways which are no longer
// in the nDF
func (hp *hostPool) UpdateNdf(ndf *ndf.NetworkDefinition) {
	select {
	case hp.newNdf <- ndf:
	default:
		jww.WARN.Printf("Failed to update the HostPool's NDF")
	}
}

// SetGatewayFilter sets the filter used to filter gateways from the ID map.
func (h *hostPool) SetGatewayFilter(f Filter) {
	h.filterMux.Lock()
	defer h.filterMux.Unlock()

	h.filter = f
}

// GetHostParams returns a copy of the connect.HostParams struct.
func (h *hostPool) GetHostParams() connect.HostParams {
	hp := h.params.HostParams
	hpCopy := connect.HostParams{
		MaxRetries:            hp.MaxRetries,
		AuthEnabled:           hp.AuthEnabled,
		EnableCoolOff:         hp.EnableCoolOff,
		NumSendsBeforeCoolOff: hp.NumSendsBeforeCoolOff,
		CoolOffTimeout:        hp.CoolOffTimeout,
		SendTimeout:           hp.SendTimeout,
		EnableMetrics:         hp.EnableMetrics,
		ExcludeMetricErrors:   make([]string, len(hp.ExcludeMetricErrors)),
		KaClientOpts:          hp.KaClientOpts,
	}
	for i := 0; i < len(hp.ExcludeMetricErrors); i++ {
		hpCopy.ExcludeMetricErrors[i] = hp.ExcludeMetricErrors[i]
	}
	return hpCopy
}

// getPool return the pool assoceated with the
func (hp *hostPool) getPool() Pool {
	p := hp.readPool.Load()
	return (p).(*pool)
}

// getFilter returns the filter used to filter gateways from the ID map.
func (h *hostPool) getFilter() Filter {
	h.filterMux.Lock()
	defer h.filterMux.Unlock()

	return h.filter
}

// getHostList returns the host list from storage.
// it will trip the list if it is too long and
// extend it if it is too short
func getHostPreparedList(kv *versioned.KV, poolSize int) ([]*id.ID, error) {
	obj, err := kv.Get(hostListKey, hostListVersion)
	if err != nil {
		return make([]*id.ID, poolSize), errors.Errorf(getStorageErr, err)
	}

	rawHL, err := unmarshalHostList(obj.Data)
	if err != nil {
		return make([]*id.ID, poolSize), err
	}

	if len(rawHL) > poolSize {
		rawHL = rawHL[:poolSize]
	} else if len(rawHL) < poolSize {
		rawHL = append(rawHL, make([]*id.ID, poolSize-len(rawHL))...)
	}

	return rawHL, nil
}

// getPoolSize determines the size of the HostPool based on the size of the NDF.
func getPoolSize(ndfLen, maxSize uint32) (uint32, error) {
	// Verify the NDF has at least one Gateway for the HostPool
	if ndfLen == 0 {
		return 0, errors.Errorf(
			"Unable to create HostPool: no gateways available")
	}

	poolSize := uint32(math.Ceil(math.Sqrt(float64(ndfLen))))
	if poolSize > maxSize {
		return maxSize, nil
	}
	return poolSize, nil
}

// getNumNodesToTest returns the number of nodes to test when
// finding a node to send messages to in order to ensure
// the pool of all nodes will not be exhausted
func getNumNodesToTest(maxPings, numGateways, poolSize int) int {
	//calculate the number of nodes to test at once
	numNodesToTest := maxPings
	accessRatio := numGateways / poolSize
	if accessRatio < 1 {
		accessRatio = 1
	}
	if numNodesToTest > accessRatio {
		numNodesToTest = accessRatio
	}
	return numNodesToTest
}
