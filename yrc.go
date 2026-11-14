package yrc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"sync"
	"time"

	"github.com/Arceliar/ironwood/types"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"golang.org/x/crypto/blake2s"
)

// TODO: Add compression
// TODO: Add PoW
// TODO: Add MaxFlyingCountDestination?
// TODO: Add per-source simultaneous receive limit
// TOOD: Add FragmentCollector timeout
// TODO: Add symmetric encryption on top?
// TODO: Message send round-robin
//       would prevent the first messages in the list from blocking latter ones from sending at all
// TODO: Make CancelMessage send a packet to notify peer to abandon the message
// TODO: Convert send progress []bool to progress []byte to reflect staged/flying/sent ternary status
// TODO: Add a way to cancel receiving message
// TODO: Add message receive timeout
// TODO: Solve potential AcceptMessage concurrency issues

const HelloInterval = time.Second*60
const AliveTimeout = time.Second*120
const RefreshInterval = time.Second*5

const MaxFlyingCountGlobal = 32
const MaxFlyingCountMessage = 8
const MaxFlyingTimeBase = time.Second*60
const MaxFlyingTimeReachable = time.Second

const NonceSize = 32

// Yggdrasil packet types
const (
	typeSessionDummy = iota // nolint:deadcode,varcheck
	typeSessionTraffic
	typeSessionProto
	
	typeYrcV1 = 42
)

// Yggdrasil protocol packet sub-types
const (
	typeProtoDummy = iota
	typeProtoNodeInfoRequest
	typeProtoNodeInfoResponse
	typeProtoDebug = 255
)

// Yrc packet sub-types
const (
	YrcHello = iota // Ping
	YrcOlleh // Pong
	YrcFrag // Fragment body
    YrcFragAck // Fragment acknowledgement
    YrcFragNak // Fragment negative acknowledgement
)

// Yrc fragmented packet types
const (
	YrcPacketMessage = iota
)

// Yrc NAK types
const (
	ErrOkay = iota // Nothing went wrong
    ErrIdontwantu // Used to explicitly indicate rejecting a peer
    ErrAlreadySent // Indicates that a message has already beeen sent
    ErrMessageTooLong // Indicates that the message is too long for the peer
    ErrBadLength // Indicates that the received fragment is not of the expected size
    ErrOutOfRange // Indicates that the received fragment index is invalid
	ErrIgnore // Indicates that, when applicable, a Nak should not be sent and the packet simply ignored
	ErrTimeout // Indicates that either receiving/sending the message has timed out
	ErrBadHash // Indicates that the received message has a hash that doesn't match the identifier's
)

const (
	fragStaged = iota
	fragFlying
	fragSent
)

// Yrc flags
const (
	flagCompression     = 0x00000003;
    flagCompressionNone = 0x00000000;
    flagCompressionZstd = 0x00000001;
)

type StagedFragment struct {
	bytes []byte
	state byte
	thrownAt time.Time
	expiresAt time.Time
}

type StagedMessage struct {
	ident Ident
	to types.Addr
	nonce [NonceSize]byte
	fragments []StagedFragment
}

func (m StagedMessage) Done() bool {
	for _, frag := range m.fragments {
		if frag.state != fragSent {
			return false
		}
	}
	return true
}

// TODO: Store as plain [64]byte?
type Ident struct {
	// blake2s-256 Hash of the base data
	Hash [32]byte
	// size of fragments
	Fragsize uint32
	// base size of the data (before compression)
	Basesize uint32
	// compressed size of the data
	Compsize uint32
	// Flags (compression)
	Flags uint32
	// packet type
	Kind uint32
	// fragment Index
	Index uint32
}

func (i Ident) FragCount() uint64 {
	return (uint64(i.Compsize) + uint64(i.Fragsize) - 1) / uint64(i.Fragsize)
}

// Parses 64 bytes into an identifier
func ParseIdent(i *Ident, src []byte) error {
	if len(src) < 64 {
		return YrcError{m: "Destination must be at least 64 bytes"}
	}
	
	copy(i.Hash[:32], src[:])
	i.Fragsize = binary.BigEndian.Uint32(src[32:])
	i.Basesize = binary.BigEndian.Uint32(src[36:])
	i.Compsize = binary.BigEndian.Uint32(src[40:])
	i.Flags = binary.BigEndian.Uint32(src[44:])
	i.Kind = binary.BigEndian.Uint32(src[48:])
	i.Index = binary.BigEndian.Uint32(src[60:])

	return nil
}

// Puts the identifier into pre-allocated bytes
// (requires 64 byte)
func (i Ident) BytesInto(dst []byte) error {
	if len(dst) < 64 {
		return YrcError{m: "Destination must be at least 64 bytes"}
	}

	copy(dst, i.Hash[:])
	binary.BigEndian.PutUint32(dst[32:], uint32(i.Fragsize))
	binary.BigEndian.PutUint32(dst[36:], uint32(i.Basesize))
	binary.BigEndian.PutUint32(dst[40:], uint32(i.Compsize))
	binary.BigEndian.PutUint32(dst[44:], uint32(i.Flags))
	binary.BigEndian.PutUint32(dst[48:], uint32(i.Kind))
	binary.BigEndian.PutUint32(dst[60:], uint32(i.Index))
	
	return nil
}

func (i Ident) Bytes() [64]byte {
	bytes := [64]byte{}
	i.BytesInto(bytes[:])
	return bytes
}

// Returns a unique key for the message, bound to a specific address
// (requires 84 bytes)
func (i Ident) MessageKeyInto(dst []byte, addr types.Addr) error {
	if len(dst) < 84 {
		return YrcError{m: "Destination must be at least 84 bytes"}
	}

	copy(dst, addr)
	copy(dst[32:], i.Hash[:])
	binary.BigEndian.PutUint32(dst[32:], uint32(i.Fragsize))
	binary.BigEndian.PutUint32(dst[36:], uint32(i.Basesize))
	binary.BigEndian.PutUint32(dst[40:], uint32(i.Compsize))
	binary.BigEndian.PutUint32(dst[44:], uint32(i.Flags))
	binary.BigEndian.PutUint32(dst[48:], uint32(i.Kind))

	return nil
}

// Returns a unique key for the message, bound to a specific address
func (i Ident) MessageKey(addr types.Addr) []byte {
	key := make([]byte, 84)
	if err := i.MessageKeyInto(key, addr); err != nil {
		panic("Something went horribly wrong")
	}
	return key
}

// Returns a unique key for the message, bound to a specific address
func (i Ident) MessageKeyHex(addr types.Addr) string {
	return hex.EncodeToString(i.MessageKey(addr))
}

type FragmentCollector struct {
	ident Ident
	// TODO: Turn into a single array?
	fragments [][]byte
	nonce [NonceSize]byte
}

type HelloEntry struct {
	addr types.Addr
	time time.Time
	refs [][84]byte
	temp bool
}

type AliveEntry struct {
	addr types.Addr
	time time.Time
}

type Yrc struct {
	Log core.Logger
	
	C *core.Core
	M *multicast.Multicast

	ctx context.Context

	receivingLock sync.RWMutex
	receiving map[[84]byte]FragmentCollector
	stagedLock sync.RWMutex
	staged map[[84]byte]StagedMessage

	// Called to control whether a packed will be considered or not
	// in cases where the packet may send a response, err can be used to control the error specified in the reply
	// (`ErrIgnore` will prevent from sending a reply at all, and `ErrOk` overrides the return value, considering it to be true instead)
	AcceptPacket func(from types.Addr, kind int, bytes []byte, err *byte) bool
	// Called to control whether a message is allowed to be received
	AcceptMessage func(from types.Addr, ident Ident, err *byte) bool

	OnSendUpdate func(to types.Addr, ident Ident, progress []bool, errCode byte)
	OnRecvUpdate func(from types.Addr, ident Ident, progress []bool, errCode byte)
	OnMessage func(from types.Addr, ident Ident, bytes []byte)

	// A list of addresses to send a hello to periodically
	helloLock sync.RWMutex
	helloList []HelloEntry
	// A list of alive addresses
	aliveLock sync.RWMutex
	aliveList []AliveEntry

	tickChan chan struct{}
}

type YrcError struct {
	m string
}

func (e YrcError) Error() string {
	return e.m;
}

// Closes the transport,
// meaning all its connections will be closed
// and it will no longer be able to process outgoing or incoming packets
func (y *Yrc) Close() {
	y.C.Close()
	y.M.Stop()
}

// Triggers process* function to be ran as soon as possible
func (y *Yrc) tick() {
	y.tickChan<- struct{}{}
}

// Adds an address to periodically send a 'hello' packet to
func (y *Yrc) AddHello(addr types.Addr) {
	y.helloLock.Lock()
	for i := range y.helloList {
		it := &y.helloList[i]
		if isSliceEq(it.addr, addr) {
			it.temp = false
			y.helloLock.Unlock()
			return
		}
	}
	y.helloList = append(y.helloList, HelloEntry{
		addr: addr, 
		time: time.Unix(0, 0), 
		refs: [][84]byte{}, 
		temp: false,
	})
	y.helloLock.Unlock()
	if _, err := y.C.PacketConn.WriteTo([]byte{typeYrcV1, YrcHello}, addr); err != types.ErrClosed {
		y.Log.Errorln(err)
	}
}

// Removes an address from the periodical 'hello' list
func (y *Yrc) RemoveHello(addr types.Addr) {
	y.helloLock.Lock()
	for i := 0; i < len(y.helloList); i++ {
		it := &y.helloList[i]
		if isSliceEq(it.addr, addr) {
			it.temp = true
			if len(it.refs) > 0 {
				y.helloLock.Unlock()
				return
			}
			lenmo := len(y.helloList)-1
			*it = y.helloList[lenmo]
			y.helloList = y.helloList[:lenmo]
			y.helloLock.Unlock()
			return
		}
	}
	y.helloLock.Unlock()
}

// Adds a temporary hello entry, linked to a specific bound identifier
func (y *Yrc) AddTempHello(addr types.Addr, key [84]byte) {
	y.helloLock.Lock()
	for i := range y.helloList {
		it := &y.helloList[i]
		if isSliceEq(it.addr, addr) {
			for j := range len(it.refs) {
				if isSliceEq(key[:], it.refs[j][:]) {
					y.helloLock.Unlock()
					return
				}
			}
			it.refs = append(it.refs, key)
			y.helloLock.Unlock()
			return
		}
	}
	y.helloList = append(y.helloList, HelloEntry{
		addr: addr, 
		time: time.Unix(0, 0), 
		refs: [][84]byte{key}, 
		temp: true,
	})
	y.helloLock.Unlock()
}

// Removes a temporary hello entry, linked to a specific bound identifier
func (y *Yrc) RemoveTempHello(addr types.Addr, key [84]byte) {
	y.helloLock.Lock()
	for i := 0; i < len(y.helloList); i++ {
		it := &y.helloList[i]
		if isSliceEq(it.addr, addr) {
			if len(it.refs) > 0 {
				if len(it.refs) == 1 {
					if !isSliceEq(it.refs[0][:], key[:]) {
						y.helloLock.Unlock()
						return
					}
				} else {
					for j := range len(it.refs) {
						if isSliceEq(it.refs[j][:], key[:]) {
							lenmo := len(it.refs)-1
							it.refs[j] = it.refs[lenmo]
							it.refs = it.refs[:lenmo]
							y.helloLock.Unlock()
							return		
						}
					}
					y.helloLock.Unlock()
					return
				}
			}
			if !it.temp {
				y.helloLock.Unlock()
				return
			}
			lenmo := len(y.helloList)-1
			*it = y.helloList[lenmo]
			y.helloList = y.helloList[:lenmo]
			y.helloLock.Unlock()
			return
		}
	}
	y.helloLock.Unlock()
}

// Checks whether an address is part of the hello list
func (y *Yrc) IsHello(addr types.Addr) bool {
	y.helloLock.RLock()
	for _, it := range y.helloList {
		if isSliceEq(it.addr, addr) {
			y.helloLock.RUnlock()
			return true
		}
	}
	y.helloLock.RUnlock()
	return false
}

// Lists all addresses in the periodical 'hello' list
func (y *Yrc) GetHelloList() []types.Addr {
	list := make([]types.Addr, len(y.helloList))
	y.helloLock.RLock()
	for i, it := range y.helloList {
		list[i] = it.addr
	}
	y.helloLock.RUnlock()
	return list
}

// Marks an address as currently alive
func (y *Yrc) AddAlive(addr types.Addr) {
	now := time.Now()
	y.aliveLock.Lock()
	for i := range y.aliveList {
		if isSliceEq(y.aliveList[i].addr, addr) {
			y.aliveList[i].time = now
			y.aliveLock.Unlock()
			return
		}
	}
	y.aliveList = append(y.aliveList, AliveEntry{addr, now})
	y.aliveLock.Unlock()
}

// Marks an address as dead
func (y *Yrc) RemoveAlive(addr types.Addr) {
	y.aliveLock.Lock()
	for i := 0; i < len(y.aliveList); {
		if isSliceEq(y.aliveList[i].addr, addr) {
			lenmo := len(y.aliveList)-1
			y.aliveList[i] = y.aliveList[lenmo]
			y.aliveList = y.aliveList[:lenmo]
			continue
		}
		i++
	}
	y.aliveLock.Unlock()
}

// Checks whether an address is alive
func (y *Yrc) IsAlive(addr types.Addr) bool {
	y.aliveLock.RLock()
	for _, it := range y.aliveList {
		if isSliceEq(it.addr, addr) {
			y.aliveLock.RUnlock()
			return time.Now().Before(it.time.Add(AliveTimeout))
		}
	}
	y.aliveLock.RUnlock()
	return false
}

// Lists all of the currently alive addresses
func (y *Yrc) GetAliveList() []types.Addr {
	list := make([]types.Addr, len(y.aliveList))
	count := 0
	now := time.Now()
	y.aliveLock.RLock()
	for _, it := range y.aliveList {
		if now.Before(it.time.Add(AliveTimeout)) {
			list[count] = it.addr
			count++
		}
	}
	y.aliveLock.RUnlock()
	return list[:count]
}

// Sends a message and returns its key
//
// TODO: Return ident instead of key?
func (y *Yrc) SendMessage(bytes []byte, to types.Addr) (key [84]byte, err error) {
	if len(bytes) >= 0xFFFFFFFF {
		err = YrcError{m: "Message too long"}
		return
	}
	// TODO: Add compression
	fragSize := min(y.FragSize(), uint32(len(bytes)))
	fragCount := ceildiv(uint32(len(bytes)), fragSize)
	ident := Ident{
		Hash: blake2s.Sum256(bytes),
		Fragsize: fragSize,
		Basesize: uint32(len(bytes)),
		Compsize: uint32(len(bytes)),
		Flags: flagCompressionNone,
		Kind: YrcPacketMessage,
	}
	fragments := make([]StagedFragment, fragCount)
	for i := range fragCount {
		frag := &fragments[i]
		frag.bytes = bytes[i*fragSize:min((i+1)*fragSize,uint32(len(bytes)))]
		frag.state = fragStaged
		frag.thrownAt = time.Unix(0, 0)
		frag.expiresAt = time.Unix(0, 0)
	}
	if err = ident.MessageKeyInto(key[:], to); err != nil {
		y.Log.Errorln(err)
		return
	}
	y.stagedLock.Lock()
	y.staged[key] = StagedMessage{
		ident: ident,
		to: to,
		nonce: [NonceSize]byte{},
		fragments: fragments,
	}
	y.stagedLock.Unlock()
	y.AddTempHello(to, key)
	go y.tick()
	return key, nil
}

// Cancels a sending message
func (y *Yrc) CancelMessage(key [84]byte) {
	y.stagedLock.Lock()
	if msg, hasMsg := y.staged[key]; hasMsg {
		y.RemoveTempHello(msg.to, key)
		delete(y.staged, key)
	}
	y.stagedLock.Unlock()
}

// Callback to handle Yrc packets
func (y *Yrc) onYrcPacket(from types.Addr, kind int, bytes []byte) error {
	reply := func(kind int, body []byte) error {
		buf := make([]byte, len(body)+2)
		buf[0] = typeYrcV1
		buf[1] = byte(kind)
		copy(buf[2:], body)
		if _, err := y.C.PacketConn.WriteTo(buf, from); err != nil {
			return err
		}
		return nil
	}

	now := time.Now()

	var ident Ident
	var messageKey [84]byte
	var identBytes [64]byte

	switch kind {		
	case YrcFrag:
		if err := ParseIdent(&ident, bytes); err != nil {
			return nil
		}
		ident.BytesInto(identBytes[:])
		ident.MessageKeyInto(messageKey[:], from)
		bytes = bytes[64:]

		err := byte(ErrIgnore)
		if y.AcceptPacket == nil || (!y.AcceptPacket(from, kind, bytes, &err) && err != ErrOkay) {
			if err != ErrIgnore {
				reply(YrcFragNak, append(identBytes[:], err))
			}
			y.receivingLock.RLock()
			if _, hasCollector := y.receiving[messageKey]; hasCollector {
				y.receivingLock.RUnlock()
				y.receivingLock.Lock()
				delete(y.receiving, messageKey)
				y.receivingLock.Unlock()
				if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, []bool{}, err)}
			} else {
				y.receivingLock.RUnlock()
			}
			return nil
		}

		y.receivingLock.Lock()
		
		// Retreive an existing fragment collector for the message, or create one if the message is unknown
		var collector FragmentCollector
		{
			var hasCollector bool
			collector, hasCollector = y.receiving[messageKey]
			if !hasCollector {
				if y.AcceptMessage == nil || (!y.AcceptMessage(from, ident, &err) && err != ErrOkay) {
					y.receivingLock.Unlock()
					if err != ErrIgnore {
						reply(YrcFragNak, append(identBytes[:], err))
					}
					return nil
				}
				var nonce [NonceSize]byte
				rand.Read(nonce[:])
				collector = FragmentCollector{
					ident: ident,
					fragments: make([][]byte, ident.FragCount()),
					nonce: nonce,
				}
				y.receiving[messageKey] = collector
			}
		}
		// TODO: Assumes collector.ident == ident, which may not be the case?
		
		// Bad fragment index
		if uint64(ident.Index) >= ident.FragCount() {
			delete(y.receiving, messageKey)
			y.receivingLock.Unlock()
			reply(YrcFragNak, append(identBytes[:], ErrOutOfRange))
			if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, []bool{}, ErrOutOfRange)}
			return nil
		}
		// Bad payload length
		if uint32(len(bytes)) != ident.Fragsize && !(uint64(ident.Index) == ident.FragCount()-1 && uint32(len(bytes)) == ident.Compsize - uint32(ident.FragCount()-1)*ident.Fragsize) {
			delete(y.receiving, messageKey)
			y.receivingLock.Unlock()
			reply(YrcFragNak, append(identBytes[:], ErrOutOfRange))
			if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, []bool{}, ErrOutOfRange)}
			return nil
		}

		collector.fragments[ident.Index] = bytes

		// Get a count and mapping of received fragments so far
		count := uint64(0)
		progress := make([]bool, ident.FragCount())
		for i, frag := range collector.fragments {
			progress[i] = frag != nil
			if frag != nil {
				count++
			}
		}
		
		// Finalize reception
		if count == collector.ident.FragCount() {
			delete(y.receiving, messageKey)
			y.receivingLock.Unlock()

			total := uint32(0)
			for _, it := range collector.fragments {
				total += uint32(len(it))
			}
			if total != ident.Compsize {
				reply(YrcFragNak, append(identBytes[:], ErrBadLength))
				if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, []bool{}, ErrBadLength)}
				return nil
			}
			raw_body := make([]byte, ident.Compsize)
			for i, frag := range collector.fragments {
				copy(raw_body[uint32(i)*ident.Fragsize:], frag)
			}
			
			var body []byte
			if ident.Flags & flagCompression != flagCompressionNone {
				body = nil
			} else {
				body = raw_body
			}
			if body == nil || uint32(len(body)) != ident.Basesize {
				reply(YrcFragNak, append(identBytes[:], ErrBadLength))
				if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, []bool{}, ErrBadLength)}
				return nil
			}

			hash := blake2s.Sum256(body)
			if !isSliceEq(hash[:], ident.Hash[:]) {
				reply(YrcFragNak, append(identBytes[:], ErrBadHash))
				if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, []bool{}, ErrBadHash)}
				return nil
			}

			if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, progress, ErrOkay)}
			if y.OnMessage != nil {y.OnMessage(from, ident, body)}
		} else {
			y.receivingLock.Unlock()
			if y.OnRecvUpdate != nil {y.OnRecvUpdate(from, ident, progress, ErrOkay)}
		}

		y.AddAlive(from)
		reply(YrcFragAck, append(identBytes[:], collector.nonce[:]...))
		return nil
		
	case YrcFragAck:
		if err := ParseIdent(&ident, bytes); err != nil {
			return nil
		}
		ident.BytesInto(identBytes[:])
		ident.MessageKeyInto(messageKey[:], from)
		var nonce [NonceSize]byte
		copy(nonce[:], bytes[64:64+NonceSize])
		bytes = bytes[64+NonceSize:]

		err := byte(ErrIgnore)
		if y.AcceptPacket == nil || (!y.AcceptPacket(from, kind, bytes, &err) && err != ErrOkay) {
			// TODO: Remove from staged?
			return nil
		}

		y.stagedLock.Lock()

		msg, hasMsg := y.staged[messageKey]
		if hasMsg && ident.Index < uint32(len(msg.fragments)) {
			isNull := isZeros(msg.nonce[:])
			progress := make([]bool, len(msg.fragments))
			if isNull || isSliceEq(msg.nonce[:], nonce[:]) {
				if isNull {
					copy(msg.nonce[:], nonce[:])
				}
				msg.fragments[ident.Index].state = fragSent
				for i := range len(msg.fragments) {
					frag := &msg.fragments[i]
					switch frag.state {
					case fragFlying:
						frag.expiresAt = now.Add(MaxFlyingTimeReachable)
					case fragSent:
						progress[i] = true
					}
				}
			} else {
				copy(msg.nonce[:], nonce[:])
				for i := range len(msg.fragments) {
					frag := &msg.fragments[i]
					if frag.state == fragFlying || frag.state == fragSent {
						frag.state = fragStaged
					}
				}
				msg.fragments[ident.Index].state = fragSent
				progress[ident.Index] = true
			}
			if y.OnSendUpdate != nil {y.OnSendUpdate(from, ident, progress, ErrOkay)}
			if msg.Done() {
				y.RemoveTempHello(msg.to, messageKey)
				delete(y.staged, messageKey)
			} else {
				y.staged[messageKey] = msg
			}
		}

		y.stagedLock.Unlock()
		y.AddAlive(from)
		go y.tick()
		return nil

	case YrcFragNak:
		if err := ParseIdent(&ident, bytes); err != nil {
			return nil
		}
		ident.BytesInto(identBytes[:])
		ident.MessageKeyInto(messageKey[:], from)
		errCode := bytes[64]
		bytes = bytes[65:]

		err := byte(ErrIgnore)
		if y.AcceptPacket == nil || (!y.AcceptPacket(from, kind, bytes, &err) && err != ErrOkay) {
			// TODO: Remove from staged?
			return nil
		}

		y.stagedLock.Lock()

		_, hasMsg := y.staged[messageKey]
		if !hasMsg {
			y.stagedLock.Unlock()
			y.AddAlive(from)
			return nil		
		}

		y.RemoveTempHello(from, messageKey)
		delete(y.staged, messageKey)

		y.stagedLock.Unlock()

		y.AddAlive(from)
		if y.OnSendUpdate != nil {y.OnSendUpdate(from, ident, []bool{}, errCode)}
		return nil
		
	case YrcHello:
		err := byte(ErrIgnore)
		if y.AcceptPacket == nil || (!y.AcceptPacket(from, kind, bytes, &err) && err != ErrOkay) {
			// TODO: Remove from hello?
			return nil
		}
		y.AddAlive(from)
		reply(YrcOlleh, bytes[:])
		return nil

	case YrcOlleh:
		err := byte(ErrIgnore)
		if y.AcceptPacket == nil || (!y.AcceptPacket(from, kind, bytes, &err) && err != ErrOkay) {
			// TODO: Remove from hello?
			return nil
		}
		y.AddAlive(from)
		go y.tick()
		return nil
	}
	
	return nil
}

// Callback to handle generic Yggdrasil packets
func (y *Yrc) onRawData(from types.Addr, bytes []byte) error {
	if len(bytes) < 1 {
		y.Log.Errorln("Missing packet kind")
		return nil
	}
	yggKind := bytes[0]
	bytes = bytes[1:]
	switch yggKind {
	case typeSessionProto:
		reqKind := bytes[0]
		bytes = bytes[1:]
		switch reqKind {
		case typeProtoNodeInfoRequest:
			_, err := y.C.PacketConn.WriteTo([]byte{2, 2, 110, 117, 108, 108}, from)
			if err != nil {
				return err
			}
		}
	case typeSessionTraffic:
		// TODO: Find a way to handle this
	case typeYrcV1:
		yrcKind := int(bytes[0])
		bytes = bytes[1:]
		return y.onYrcPacket(from, yrcKind, bytes)
	}
	return  nil
}

// Returns the maximum size for a fragment's body
func (y *Yrc) FragSize() uint32 {
	// clamps MTU to 32 bits
	// theoretically impossible lmfao
	return uint32(min(y.C.MTU() - 64 - 2, 0xFFFFFFFF))
}

// Process staged messages
func (y *Yrc) processStaged() {
	if len(y.staged) == 0 {
		return
	}

	now := time.Now()

	flying := 0

	y.stagedLock.Lock()
	
	for key := range y.staged {
		msg := y.staged[key]
		if msg.Done() {
			y.RemoveTempHello(msg.to, key)
			delete(y.staged, key)
			continue
		}
		
		updated := false
		// TODO: Get alive list and then look up inside it
		if !y.IsAlive(msg.to) {
			// stage back all flying fragments to a dead peer
			for i := range msg.fragments {
				frag := &msg.fragments[i]
				if frag.state == fragFlying {
					frag.state = fragStaged
					updated = true
				}
			}
		} else {
			// stage back flying fragments are in flight for too long
			for i := range msg.fragments {
				frag := &msg.fragments[i]
				if frag.state == fragFlying {
					if frag.expiresAt.Before(now) {
						frag.state = fragStaged
						updated = true
					} else {
						flying++
					}
				}
			}
		}
		if updated {
			y.staged[key] = msg
		}
	}
	
	if flying >= MaxFlyingCountGlobal {
		y.stagedLock.Unlock()
		return
	}
	
	for key := range y.staged {
		msg := y.staged[key]
		// TODO: Get alive list and then look up inside it
		if !y.IsAlive(msg.to) {
			continue
		}
		
		count := 0
		for i := range msg.fragments {
			frag := &msg.fragments[i]
			if frag.state == fragFlying {
				count++
			}
		}
		if count >= MaxFlyingCountMessage {
			continue
		}
		
		updated := false
		for i := range msg.fragments {
			frag := &msg.fragments[i]
			if frag.state == fragStaged {
				count++
				flying++
				updated = true

				frag.state = fragFlying
				frag.thrownAt = now
				frag.expiresAt = now.Add(MaxFlyingTimeBase)
				
				pkt := make([]byte, len(frag.bytes)+66)
				pkt[0] = typeYrcV1
				pkt[1] = YrcFrag
				ident := msg.ident
				ident.Index = uint32(i)
				ident.BytesInto(pkt[2:])
				copy(pkt[66:], frag.bytes)
				
				_, err := y.C.PacketConn.WriteTo(pkt, msg.to)
				if err != nil {
					y.Log.Errorln(err)
					return
				}

				if count >= MaxFlyingCountMessage || flying >= MaxFlyingCountGlobal {
					break
				}
			}
		}
		if updated {
			y.staged[key] = msg
		}
	}
	y.stagedLock.Unlock()
}

// Process pending 'hello' transmissions
func (y *Yrc) processHello() {
	now := time.Now()
	y.helloLock.Lock()
	for i := range y.helloList {
		it := &y.helloList[i]
		if now.Sub(it.time) >= HelloInterval && (!it.temp || len(it.refs) > 0) {
			it.time = now
			_, err := y.C.PacketConn.WriteTo([]byte{typeYrcV1, YrcHello}, it.addr)
			if err != nil {
				if err != types.ErrClosed {
					y.Log.Errorln(err)
				}
				return
			}
		}
	}
	y.helloLock.Unlock()
}

// Purge stale alive entries
func (y *Yrc) processAlive() {
	now := time.Now()
	y.aliveLock.Lock()
	for i := 0; i < len(y.aliveList); {
		if now.Sub(y.aliveList[i].time) >= AliveTimeout {
			lenmo := len(y.aliveList)-1
			y.aliveList[i] = y.aliveList[lenmo]
			y.aliveList = y.aliveList[:lenmo]
			continue
		}
		i++
	}
	y.aliveLock.Unlock()
}

// Loop that receives from Ironwood directly and dispatches to the Yrc instance
//
// should never be called outside of New
func (y *Yrc) recvLoop() {
	defer y.Close()
	
	if y.C.PacketConn.MTU() < 128 {
		panic("MTU is insufficient")
	}
	
	bytes := make([]byte, y.C.PacketConn.MTU())
	for {
		n, from, err := y.C.PacketConn.ReadFrom(bytes)
		if err != nil {
			y.Log.Errorln(err)
			return
		}
		go func(bytes []byte) {
			if err := y.onRawData(from.(types.Addr), bytes); err != nil {
				y.Log.Errorln(err)
				y.Close()
			}
		}(cloneSlice(bytes[:n]))
	}
}

// Loop that runs the process* functions every so often
//
// should never be called outside of New
func (y *Yrc) processLoop() {
	defer y.Close()
	for {
		done, cancel := context.WithTimeout(y.ctx, RefreshInterval)
		
		wait: for {
			select {
			case <-done.Done():
				if done.Err() == context.Canceled {
					cancel()
					return
				}
				break wait
			case <-y.tickChan:
				break wait
			}
		}
		
		cancel()

		y.processHello()
		y.processAlive()
		y.processStaged()
	}
}

func SetupYggdrasil(logger core.Logger, key config.KeyBytes) (c *core.Core, m *multicast.Multicast, err error) {
	cfg := config.GenerateConfig()

	// Basic config
	{
		cfg.PrivateKey = key
		cfg.AdminListen = "none"
		cfg.NodeInfoPrivacy = true // kinda useless
	}

	cfg.GenerateSelfSignedCertificate()

	privateKey := ed25519.PrivateKey(cfg.PrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Setup core
	{
		options := []core.SetupOption{
			core.NodeInfo(cfg.NodeInfo),
			core.NodeInfoPrivacy(cfg.NodeInfoPrivacy),
		}
		for _, addr := range cfg.Listen {
			options = append(options, core.ListenAddress(addr))
		}
		for _, peer := range cfg.Peers {
			options = append(options, core.Peer{URI: peer})
		}
		for intf, peers := range cfg.InterfacePeers {
			for _, peer := range peers {
				options = append(options, core.Peer{URI: peer, SourceInterface: intf})
			}
		}
		for _, allowed := range cfg.AllowedPublicKeys {
			k, err := hex.DecodeString(allowed)
			if err != nil {
				panic(err)
			}
			options = append(options, core.AllowedPublicKey(k[:]))
		}
		if c, err = core.New(cfg.Certificate, logger, options...); err != nil {
			return
		}
	}

	// Setup multicast
	{
		options := []multicast.SetupOption{}
		for _, intf := range cfg.MulticastInterfaces {
			options = append(options, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}
		if m, err = multicast.New(c, logger, options...); err != nil {
			return
		}
	}

	logger.Debugln("Connected", hex.EncodeToString(publicKey))

	return
}

func New(key config.KeyBytes, logger core.Logger, ctx context.Context) (*Yrc, error) {
	c, m, err := SetupYggdrasil(logger, key)

	if err != nil {
		return nil, err
	}

	y := &Yrc{
		Log: logger,

		C: c,
		M: m,

		ctx: ctx,

		receivingLock: sync.RWMutex{},
		receiving: make(map[[84]byte]FragmentCollector),
		stagedLock: sync.RWMutex{},
		staged: make(map[[84]byte]StagedMessage),

		AcceptPacket: nil,
		AcceptMessage: nil,

		helloLock: sync.RWMutex{},
		helloList: []HelloEntry{},
		aliveLock: sync.RWMutex{},
		aliveList: []AliveEntry{},

		tickChan: make(chan struct{}),
	}

	go y.recvLoop()
	go y.processLoop()

	return y, nil
}
