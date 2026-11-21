package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*MultiUserServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewMultiServer(ctx, config.(*MultiUserServerConfig))
	}))
}

type MultiUserInbound struct {
	// Removal needs exclusive access while UDP authenticates/assigns
	// session users. Multiple active UDP decryptions may share read lock.
	sync.RWMutex
	networks        []net.Network
	method          *CipherMethod
	masterPSK       []byte
	usersByHash     *utils.TypedSyncMap[[AESBlockSize]byte, *protocol.MemoryUser]
	usersByEmail    *utils.TypedSyncMap[string, *protocol.MemoryUser]
	userCount       atomic.Int64
	saltFilter      *antireplay.ReplayFilter[[32]byte]
	udpSessions     *UDPSessionManager
	// Protected by the same inbound RWMutex as live user authentication.
	// A successful user removal closes all accepted original TCP sockets.
	tcpConnections map[*protocol.MemoryUser]map[*liB05TCPBinding]struct{}
	udpMasterCipher cipher.Block
	policyManager   policy.Manager
}

func NewMultiServer(ctx context.Context, config *MultiUserServerConfig) (*MultiUserInbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}

	method, err := GetCipherMethod(config.Method)
	if err != nil {
		return nil, err
	}
	if method.IsChaCha {
		return nil, errors.New("shadowsocks 2022 multi-user: only aes methods are supported")
	}

	masterPSK, err := ParseKey(config.Key, method.KeySaltLength)
	if err != nil {
		return nil, err
	}

	masterBlock, err := method.NewBlock(masterPSK)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	i := &MultiUserInbound{
		networks:        networks,
		method:          method,
		masterPSK:       masterPSK,
		usersByHash:     utils.NewTypedSyncMap[[AESBlockSize]byte, *protocol.MemoryUser](),
		usersByEmail:    utils.NewTypedSyncMap[string, *protocol.MemoryUser](),
		saltFilter:      antireplay.NewMapFilter[[32]byte](60),
		udpSessions:     NewUDPSessionManager(500 * time.Second),
		tcpConnections:  make(map[*protocol.MemoryUser]map[*liB05TCPBinding]struct{}),
		udpMasterCipher: masterBlock,
		policyManager:   v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	for idx, user := range config.Users {
		if user.Email == "" {
			u := uuid.New()
			user.Email = "unnamed-user-" + strconv.Itoa(idx) + "-" + u.String()
		}
		memUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to parse shadowsocks user").Base(err)
		}
		if err := i.AddUser(ctx, memUser); err != nil {
			return nil, err
		}
	}

	return i, nil
}

// AddUser implements proxy.UserManager.AddUser()
func (i *MultiUserInbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	i.Lock()
	defer i.Unlock()

	var emailKey string
	if u.Email != "" {
		emailKey = strings.ToLower(u.Email)
		if _, exists := i.usersByEmail.Load(emailKey); exists {
			return errors.New("user ", u.Email, " already exists")
		}
	}

	memAcc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("missing or invalid user account")
	}

	if len(memAcc.Key) != i.method.KeySaltLength {
		return ErrBadKey
	}

	pskHash := DeriveUserPSKHash(memAcc.Key)
	// Distinct accounts MUST NOT share a PSK/EIH identity: otherwise the
	// second add silently replaces the first user's hash mapping and traffic
	// can be attributed to the wrong UID before either account is deleted.
	if _, exists := i.usersByHash.Load(pskHash); exists {
		return errors.New("duplicate shadowsocks 2022 user PSK identity refused")
	}
	i.usersByHash.Store(pskHash, u)
	if emailKey != "" {
		i.usersByEmail.Store(emailKey, u)
	}
	i.userCount.Add(1)

	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser()
func (i *MultiUserInbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("email must not be empty")
	}

	i.Lock()
	defer i.Unlock()

	emailKey := strings.ToLower(email)
	u, loaded := i.usersByEmail.LoadAndDelete(emailKey)
	if !loaded {
		return errors.New("user ", email, " not found")
	}

	pskHash := DeriveUserPSKHash(u.Account.(*MemoryAccount).Key)
	i.usersByHash.Delete(pskHash)
	// The deletion lock excludes all new native TCP authentication. Close
	// accepted original sockets while still holding this fence. This also
	// interrupts a handshake authenticated immediately before deletion.
	for binding := range i.tcpConnections[u] {
		_ = binding.conn.Close()
	}
	delete(i.tcpConnections, u)
	// Invalidate sessions that previously resolved this exact account. Merely
	// removing the hash does NOT invalidate sessionItem.User/UserPSK caches.
	// The handler's exclusive lock excludes new cached-user assignment.
	if i.udpSessions != nil {
		i.udpSessions.RevokeUser(u)
	}
	i.userCount.Add(-1)

	return nil
}

// GetUser implements proxy.UserManager.GetUser()
func (i *MultiUserInbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	u, _ := i.usersByEmail.Load(strings.ToLower(email))
	return u
}

// GetUsers implements proxy.UserManager.GetUsers()
func (i *MultiUserInbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	var users []*protocol.MemoryUser
	i.usersByEmail.Range(func(_ string, user *protocol.MemoryUser) bool {
		users = append(users, user)
		return true
	})
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount()
func (i *MultiUserInbound) GetUsersCount(context.Context) int64 {
	return i.userCount.Load()
}

func (i *MultiUserInbound) Network() []net.Network {
	return i.networks
}

func (i *MultiUserInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-multi"
	inbound.CanSpliceCopy = 3

	if network == net.Network_TCP {
		return i.processTCP(ctx, connection, dispatcher)
	}
	return i.processUDP(ctx, connection, dispatcher)
}

// liB05TCPBinding is a unique, comparable handle for the original TCP socket.
// A re-added account must never inherit bindings owned by the retired pointer.
type liB05TCPBinding struct {
	user *protocol.MemoryUser
	conn net.Conn
}

// liB05BindTCPUser atomically checks live EIH identity and registers the
// actual transport socket. RemoveUser holds the same exclusive lock, so
// either the old binding is closed by removal or new binding is refused.
func (i *MultiUserInbound) liB05BindTCPUser(hash [AESBlockSize]byte, conn net.Conn) (*liB05TCPBinding, bool) {
	i.Lock()
	defer i.Unlock()
	user, ok := i.usersByHash.Load(hash)
	if !ok || user == nil || conn == nil {
		return nil, false
	}
	if i.tcpConnections == nil {
		i.tcpConnections = make(map[*protocol.MemoryUser]map[*liB05TCPBinding]struct{})
	}
	binding := &liB05TCPBinding{user: user, conn: conn}
	if i.tcpConnections[user] == nil {
		i.tcpConnections[user] = make(map[*liB05TCPBinding]struct{})
	}
	i.tcpConnections[user][binding] = struct{}{}
	return binding, true
}

// Keep the original socket registered until it is actually closed.
func (i *MultiUserInbound) liB05UnbindTCPUser(binding *liB05TCPBinding) {
	if binding == nil {
		return
	}
	i.Lock()
	defer i.Unlock()
	if active := i.tcpConnections[binding.user]; active != nil {
		delete(active, binding)
		if len(active) == 0 {
			delete(i.tcpConnections, binding.user)
		}
	}
}

func (i *MultiUserInbound) processTCP(ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) error {
	defer conn.Close()

	sessionPolicy := i.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err)
	}

	// 1. Single read call for Salt + EIH + Fixed-length header chunk per SIP022 §3.1.4
	headerLen := i.method.KeySaltLength + AESBlockSize + RequestHeaderFixedChunkLength + AEADTagSize
	headerBuf := make([]byte, headerLen)
	n, err := conn.Read(headerBuf)
	if err != nil || n < headerLen {
		ResetTCPConn(conn)
		return errors.New("failed to read complete handshake header")
	}

	var salt [32]byte
	copy(salt[:i.method.KeySaltLength], headerBuf[:i.method.KeySaltLength])
	saltSlice := salt[:i.method.KeySaltLength]
	eih := headerBuf[i.method.KeySaltLength : i.method.KeySaltLength+AESBlockSize]
	fixedChunk := headerBuf[i.method.KeySaltLength+AESBlockSize:]

	decryptedHash, err := DecryptEIH(i.method, i.masterPSK, saltSlice, eih)
	if err != nil {
		ResetTCPConn(conn)
		return err
	}

	// Authenticate and register the original TCP transport under the same
	// user-removal fence. A plain usersByHash.Load could authorize a removed
	// account immediately before deletion and leave its stream alive.
	binding, ok := i.liB05BindTCPUser(decryptedHash, conn)
	if !ok {
		ResetTCPConn(conn)
		return ErrInvalidRequest
	}
	defer func() {
		// Close before untracking: RemoveUser must never observe a
		// deregistered, still-writable old account socket.
		_ = conn.Close()
		i.liB05UnbindTCPUser(binding)
	}()
	user := binding.user
	userPSK := user.Account.(*MemoryAccount).Key

	reader, reqHeader, err := InitServerStream(conn, i.method, userPSK, saltSlice, salt, fixedChunk, i.saltFilter)
	if err != nil {
		ResetTCPConn(conn)
		return err
	}

	dest := reqHeader.Destination

	writer := NewServerStreamWriter(conn, i.method, userPSK, saltSlice)

	// Dispatch Connection to Xray routing with matched User
	inbound := session.InboundFromContext(ctx)
	inbound.User = user

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})

	errors.LogInfo(ctx, "tunneling request to ", dest, " for user ", user.Email)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	if len(reqHeader.EarlyData) > 0 {
		mb := buf.MergeBytes(nil, reqHeader.EarlyData)
		if err := link.Writer.WriteMultiBuffer(mb); err != nil {
			return err
		}
	}

	return TransportTCP(ctx, i.policyManager.ForLevel(user.Level), reader, writer, link)
}

func (i *MultiUserInbound) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := buf.NewPacketReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}

		for _, b := range mb {
			// In multi-user UDP:
			// Packet header is 16 bytes: Encrypted(SessionID + PacketID)
			// Followed by 16 bytes EIH
			packetBytes := b.Bytes()
			if len(packetBytes) < 32+1+8+2 {
				b.Release()
				continue
			}

			var rawHeader [16]byte
			i.udpMasterCipher.Decrypt(rawHeader[:], packetBytes[:16])

			sessionID := binary.BigEndian.Uint64(rawHeader[:8])
			packetID := binary.BigEndian.Uint64(rawHeader[8:16])

			sessionItem := i.udpSessions.GetOrCreate(sessionID)

			if !sessionItem.CheckPacketID(packetID) {
				b.Release()
				continue
			}

			// Every native UDP packet must resolve its authenticated EIH against
			// the LIVE user map, including packets of an already cached SessionID.
			// A removed user cannot rely on sessionItem.UserPSK to bypass revoke.
			decryptedHash := DecryptUDPEIH(i.udpMasterCipher, rawHeader[:], packetBytes[16:32])
			i.RLock()
			sessionItem.Lock()
			cached := sessionItem.User
			revoked := sessionItem.revoked.Load()
			sessionItem.Unlock()
			currentUser, userPSK, active := i.liB05LiveUDPUser(decryptedHash, cached)
			if revoked || !active {
				i.RUnlock()
				b.Release()
				continue
			}

			decoded, err := sessionItem.DecryptAESPayload(i.method, userPSK, sessionID, packetID, rawHeader[:], packetBytes[32:])
			b.Release()
			if err != nil {
				i.RUnlock()
				continue
			}

			sessionItem.Lock()
			if sessionItem.revoked.Load() || (sessionItem.User != nil && sessionItem.User != currentUser) {
				sessionItem.Unlock()
				i.RUnlock()
				continue
			}
			if sessionItem.User == nil {
				sessionItem.User = currentUser
				sessionItem.UserPSK = userPSK
			}
			sessionItem.Unlock()
			i.RUnlock()

			// Exclusive RemoveUser may have invalidated the session immediately
			// after the read lock. The downstream final socket and EnsureLink
			// independently reject the revoked bit as well.
			if sessionItem.revoked.Load() {
				continue
			}
			link := sessionItem.link.Load()
			if link != nil {
				sessionItem.UpdateConn(conn)
			} else {
				var err error
				link, err = sessionItem.EnsureLink(ctx, conn, decoded.Destination, dispatcher, i.policyManager, func(replyDest net.Destination, payload []byte) ([]byte, error) {
					return i.encodeServerUDPPacket(sessionID, userPSK, replyDest, payload)
				})
				if err != nil {
					continue
				}
			}

			if sessionItem.revoked.Load() {
				continue
			}
			pBuf := buf.New()
			pBuf.Write(decoded.Payload)
			pBuf.UDP = &decoded.Destination
			_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{pBuf})
		}
	}
}

func (i *MultiUserInbound) encodeServerUDPPacket(clientSessionID uint64, userPSK []byte, dest net.Destination, payload []byte) ([]byte, error) {
	return i.udpSessions.EncodeServerPacket(i.method, userPSK, clientSessionID, dest, payload)
}

// liB05LiveUDPUser is called under MultiUserInbound.RLock, held across
// authenticated packet decryption and cached session ownership assignment.
// The cached pointer may ONLY equal a user still present under the exact
// EIH-derived hash. In particular RemoveUser + re-add with the same key
// cannot revive an old session pointer/nonce/link.
func (i *MultiUserInbound) liB05LiveUDPUser(hash [AESBlockSize]byte, cached *protocol.MemoryUser) (*protocol.MemoryUser, []byte, bool) {
	user, ok := i.usersByHash.Load(hash)
	if !ok || user == nil || (cached != nil && cached != user) {
		return nil, nil, false
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok || len(account.Key) != i.method.KeySaltLength {
		return nil, nil, false
	}
	return user, account.Key, true
}
