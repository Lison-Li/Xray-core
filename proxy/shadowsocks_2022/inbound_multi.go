package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	A "github.com/sagernet/sing/common/auth"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*MultiUserServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewMultiServer(ctx, config.(*MultiUserServerConfig))
	}))
}

type MultiUserInbound struct {
    sync.Mutex
    networks []net.Network
    users []*protocol.MemoryUser // stable presentation order, never lookup by callback index
    userIDs []int // parallel to users; monotonically allocated, never reused
    userByID map[int]*protocol.MemoryUser // authenticated sing-shadowsocks ID -> original user
    nextUserID int
    service *shadowaead_2022.MultiService[int]
}

func NewMultiServer(ctx context.Context, config *MultiUserServerConfig) (*MultiUserInbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}
	memUsers := []*protocol.MemoryUser{}
	for i, user := range config.Users {
		if user.Email == "" {
			u := uuid.New()
			user.Email = "unnamed-user-" + strconv.Itoa(i) + "-" + u.String()
		}
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get shadowsocks user").Base(err).AtError()
		}
		memUsers = append(memUsers, u)
	}

	userIDs := make([]int,len(memUsers))
    userByID := make(map[int]*protocol.MemoryUser,len(memUsers))
    for id, u := range memUsers {
        userIDs[id] = id
        userByID[id] = u
    }
    inbound := &MultiUserInbound{
        networks: networks,
        users: memUsers,
        userIDs: userIDs,
        userByID: userByID,
        nextUserID: len(memUsers),
    }
	if config.Key == "" {
		return nil, errors.New("missing key")
	}
	psk, err := base64.StdEncoding.DecodeString(config.Key)
	if err != nil {
		return nil, errors.New("parse config").Base(err)
	}
	service, err := shadowaead_2022.NewMultiService[int](config.Method, psk, 500, inbound, nil)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}
	err = service.UpdateUsersWithPasswords(
		C.MapIndexed(memUsers, func(index int, it *protocol.MemoryUser) int { return userIDs[index] }),
		C.Map(memUsers, func(it *protocol.MemoryUser) string { return it.Account.(*MemoryAccount).Key }),
	)
	if err != nil {
		return nil, errors.New("create service").Base(err)
	}

	inbound.service = service
	return inbound, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (i *MultiUserInbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
    if u==nil || u.Email=="" {
        return errors.New("SS2022 AddUser requires nonempty authenticated user identity")
    }
    account,ok:=u.Account.(*MemoryAccount)
    if !ok || account.Key=="" {
        return errors.New("SS2022 AddUser requires validated encrypted user account")
    }
    i.Lock()
    defer i.Unlock()
    for _, old:=range i.users {
        if strings.EqualFold(old.Email,u.Email) {
            return errors.New("User ",u.Email," already exists.")
        }
    }
    if i.nextUserID==int(^uint(0)>>1) {
        return errors.New("SS2022 authenticated user index exhausted; refusing reused identity")
    }
    // Never reuse a key even when UpdateUsersWithPasswords fails ambiguously.
    id:=i.nextUserID
    i.nextUserID++
    candidateUsers:=append(append([]*protocol.MemoryUser(nil),i.users...),u)
    candidateIDs:=append(append([]int(nil),i.userIDs...),id)
    err:=i.service.UpdateUsersWithPasswords(
        C.MapIndexed(candidateUsers,func(index int,it *protocol.MemoryUser)int{return candidateIDs[index]}),
        C.Map(candidateUsers,func(it *protocol.MemoryUser)string{return it.Account.(*MemoryAccount).Key}),
    )
    if err!=nil {return errors.New("SS2022 AddUser service update rejected; identity not activated").Base(err)}
    i.users=candidateUsers
    i.userIDs=candidateIDs
    if i.userByID==nil {i.userByID=make(map[int]*protocol.MemoryUser)}
    i.userByID[id]=u
    return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (i *MultiUserInbound) RemoveUser(ctx context.Context, email string) error {
    if email=="" {return errors.New("Email must not be empty.")}
    i.Lock()
    defer i.Unlock()
    idx:=-1
    for j,u:=range i.users {
        if strings.EqualFold(u.Email,email) {idx=j;break}
    }
    if idx==-1 {return errors.New("User ",email," not found.")}
    removedID:=i.userIDs[idx]
    // Never swap a surviving user into the removed ID: the sing-shadowsocks
    // NAT/packet callback can still carry that integer from an older session.
    // A stale callback MUST fail closed, never bind to a second user's WAL.
    candidateUsers:=make([]*protocol.MemoryUser,0,len(i.users)-1)
    candidateIDs:=make([]int,0,len(i.userIDs)-1)
    candidateUsers=append(candidateUsers,i.users[:idx]...)
    candidateUsers=append(candidateUsers,i.users[idx+1:]...)
    candidateIDs=append(candidateIDs,i.userIDs[:idx]...)
    candidateIDs=append(candidateIDs,i.userIDs[idx+1:]...)
    err:=i.service.UpdateUsersWithPasswords(
        C.MapIndexed(candidateUsers,func(index int,it *protocol.MemoryUser)int{return candidateIDs[index]}),
        C.Map(candidateUsers,func(it *protocol.MemoryUser)string{return it.Account.(*MemoryAccount).Key}),
    )
    if err!=nil {return errors.New("SS2022 RemoveUser service update failed; original map kept").Base(err)}
    delete(i.userByID,removedID)
    i.users=candidateUsers
    i.userIDs=candidateIDs
    return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (i *MultiUserInbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	i.Lock()
	defer i.Unlock()

	for _, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (i *MultiUserInbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	i.Lock()
	defer i.Unlock()
	dst := make([]*protocol.MemoryUser, len(i.users))
	copy(dst, i.users)
	return dst
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (i *MultiUserInbound) GetUsersCount(context.Context) int64 {
	i.Lock()
	defer i.Unlock()
	return int64(len(i.users))
}

func (i *MultiUserInbound) Network() []net.Network {
    return i.networks
}

// The authentication library passes back its original integer user ID.
// Resolve ONLY an ID that remains in the current service registration.
// Never index a mutable users slice: deletion formerly swapped user N into
// another active user's old index, allowing identity aliases and panics.
func (i *MultiUserInbound) liB05AuthenticatedUserByID(id int) (*protocol.MemoryUser,error) {
    i.Lock()
    user:=i.userByID[id]
    i.Unlock()
    if user==nil || user.Email=="" {
        return nil,errors.New("SS2022 removed/unknown authenticated user ID; fail closed")
    }
    return user,nil
}

func (i *MultiUserInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-multi"
	inbound.CanSpliceCopy = 3

	var metadata M.Metadata
	if inbound.Source.IsValid() {
		metadata.Source = M.ParseSocksaddr(inbound.Source.NetAddr())
	}

	ctx = session.ContextWithDispatcher(ctx, dispatcher)

	if network == net.Network_TCP {
		return singbridge.ReturnError(i.service.NewConnection(ctx, connection, metadata))
	} else {
		reader := buf.NewReader(connection)
		pc := &natPacketConn{connection}
		for {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(mb)
				return singbridge.ReturnError(err)
			}
			for _, buffer := range mb {
				packet := B.As(buffer.Bytes()).ToOwned()
				buffer.Release()
				err = i.service.NewPacket(ctx, pc, packet, metadata)
				if err != nil {
					packet.Release()
					buf.ReleaseMulti(mb)
					return err
				}
			}
		}
	}
}

func (i *MultiUserInbound) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
    inbound:=session.InboundFromContext(ctx)
    userInt, authenticated:=A.UserFromContext[int](ctx)
    if !authenticated || inbound==nil {
        return errors.New("SS2022 TCP authenticated context missing; fail closed")
    }
    user,err:=i.liB05AuthenticatedUserByID(userInt)
    if err!=nil {return err}
    inbound.User=user
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to tcp:", metadata.Destination)
	dispatcher := session.DispatcherFromContext(ctx)
	destination := singbridge.ToDestination(metadata.Destination, net.Network_TCP)
	if !destination.IsValid() {
		return errors.New("invalid destination")
	}

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	return singbridge.CopyConn(ctx, conn, link, conn)
}

func (i *MultiUserInbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
    inbound:=session.InboundFromContext(ctx)
    userInt,authenticated:=A.UserFromContext[int](ctx)
    if !authenticated || inbound==nil {
        return errors.New("SS2022 UDP authenticated context missing; fail closed")
    }
    user,err:=i.liB05AuthenticatedUserByID(userInt)
    if err!=nil {return err}
    inbound.User=user
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   metadata.Source,
		To:     metadata.Destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to udp:", metadata.Destination)
	dispatcher := session.DispatcherFromContext(ctx)
	destination := singbridge.ToDestination(metadata.Destination, net.Network_UDP)
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	outConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   destination,
	}
    // For the separately dual-opted native UDP QA only, ensure a downlink
    // WAL receipt arrives AFTER the sing-shadowsocks encrypted server packet
    // has traversed the original natPacketConn socket. Ordinary SS2022
    // mode remains untouched; partial QA flags refuse forwarding.
    originalConn, err := liB05SS2022NativeUDPWrapOriginal(ctx, link.Reader, conn)
    if err != nil { return err }
	return bufio.CopyPacketConn(ctx, originalConn, outConn)
}

func (i *MultiUserInbound) NewError(ctx context.Context, err error) {
	if E.IsClosed(err) {
		return
	}
	errors.LogWarning(ctx, err.Error())
}
