// Derived from wyx2685/Xray-core 83ad74c46335, transport/internet/tuic.
// Licensed under MPL-2.0; see LICENSE and README.md in this directory.

package tuic

import (
	"bytes"
	"context"
	"encoding/binary"
	stderrors "errors"
	"io"
	"math"
	stdnet "net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

type PacketConn interface {
	stdnet.Conn
	ReadPacket() ([]byte, xnet.Destination, error)
	WritePacket([]byte, xnet.Destination) error
}

type udpMessage struct {
	sessionID     uint16
	packetID      uint16
	fragmentTotal uint8
	fragmentID    uint8
	destination   xnet.Destination
	data          []byte
}

func (m *udpMessage) pack() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, m.headerSize()+len(m.data)))
	buffer.WriteByte(tuicVersion)
	buffer.WriteByte(commandPacket)
	if err := binary.Write(buffer, binary.BigEndian, m.sessionID); err != nil {
		return nil, err
	}
	if err := binary.Write(buffer, binary.BigEndian, m.packetID); err != nil {
		return nil, err
	}
	if err := binary.Write(buffer, binary.BigEndian, m.fragmentTotal); err != nil {
		return nil, err
	}
	if err := binary.Write(buffer, binary.BigEndian, m.fragmentID); err != nil {
		return nil, err
	}
	if err := binary.Write(buffer, binary.BigEndian, uint16(len(m.data))); err != nil {
		return nil, err
	}
	if err := writeDestination(buffer, m.destination); err != nil {
		return nil, err
	}
	buffer.Write(m.data)
	return buffer.Bytes(), nil
}

func (m *udpMessage) headerSize() int {
	return 10 + destinationLen(m.destination)
}

func fragUDPMessage(message *udpMessage, maxPacketSize int) []*udpMessage {
	udpMTU := maxPacketSize - message.headerSize()
	if udpMTU <= 0 || len(message.data) <= udpMTU {
		return []*udpMessage{message}
	}
	var fragments []*udpMessage
	originPacket := message.data
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := *message
		if remaining > udpMTU {
			fragment.data = originPacket[:udpMTU]
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = originPacket
			originPacket = nil
		}
		fragments = append(fragments, &fragment)
	}
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(len(fragments))
		if index > 0 {
			fragment.destination = xnet.Destination{}
		}
	}
	return fragments
}

var _ PacketConn = (*udpPacketConn)(nil)

type udpPacketConn struct {
	ctx          context.Context
	cancel       context.CancelCauseFunc
	sessionID    uint16
	quicConn     *quic.Conn
	data         chan *udpMessage
	udpStream    bool
	udpMTU       int
	packetID     atomic.Uint32
	closeOnce    sync.Once
	isServer     bool
	defragger    *udpDefragger
	onDestroy    func()
	readDeadline packetDeadline
	startAccess  sync.Mutex
	started      bool
	user         *protocol.MemoryUser
}

func newUDPPacketConn(ctx context.Context, quicConn *quic.Conn, udpStream bool, isServer bool, user *protocol.MemoryUser, onDestroy func()) *udpPacketConn {
	ctx, cancel := context.WithCancelCause(ctx)
	return &udpPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		quicConn:     quicConn,
		data:         make(chan *udpMessage, 64),
		udpStream:    udpStream,
		isServer:     isServer,
		defragger:    newUDPDefragger(),
		onDestroy:    onDestroy,
		udpMTU:       1200 - 3,
		readDeadline: newPacketDeadline(),
		user:         user,
	}
}

func (c *udpPacketConn) User() *protocol.MemoryUser {
	return c.user
}

func (c *udpPacketConn) done() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
		return false
	}
}

func (c *udpPacketConn) markStarted(destination xnet.Destination) bool {
	if !destination.IsValid() {
		return false
	}
	c.startAccess.Lock()
	defer c.startAccess.Unlock()
	if c.started {
		return false
	}
	c.started = true
	return true
}

func (c *udpPacketConn) ReadPacket() ([]byte, xnet.Destination, error) {
	select {
	case p := <-c.data:
		if p == nil {
			return nil, xnet.Destination{}, io.ErrClosedPipe
		}
		return p.data, p.destination, nil
	case <-c.ctx.Done():
		return nil, xnet.Destination{}, io.ErrClosedPipe
	case <-c.readDeadline.wait():
		return nil, xnet.Destination{}, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr stdnet.Addr, err error) {
	data, destination, err := c.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, data)
	return n, destinationAddr{destination: destination}, nil
}

func (c *udpPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *udpPacketConn) WritePacket(data []byte, destination xnet.Destination) error {
	select {
	case <-c.ctx.Done():
		return stdnet.ErrClosed
	default:
	}
	if len(data) > 0xffff {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	if !destination.IsValid() {
		return os.ErrInvalid
	}
	packetID := uint16(c.packetID.Add(1) % math.MaxUint16)
	message := &udpMessage{
		sessionID:     c.sessionID,
		packetID:      packetID,
		fragmentTotal: 1,
		destination:   destination,
		data:          data,
	}
	return c.writePacketOrFragments(message, len(data))
}

func (c *udpPacketConn) WriteTo(p []byte, addr stdnet.Addr) (n int, err error) {
	destination, err := destinationFromNetAddr(addr, xnet.Network_UDP)
	if err != nil {
		return 0, err
	}
	if err = c.WritePacket(p, destination); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.quicConn.RemoteAddr())
}

func (c *udpPacketConn) writePacketOrFragments(message *udpMessage, dataLen int) error {
	var err error
	if !c.udpStream && dataLen > c.udpMTU-message.headerSize() {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !stderrors.As(err, &tooLargeErr) {
		return err
	}
	c.udpMTU = int(tooLargeErr.MaxDatagramPayloadSize) - 3
	return c.writePackets(fragUDPMessage(message, c.udpMTU))
}

func (c *udpPacketConn) inputPacket(message *udpMessage) {
	if message.fragmentTotal <= 1 {
		if c.isServer {
			errors.LogDebug(c.ctx, "TUIC received UDP packet on session=", c.sessionID, " size=", len(message.data), " dest=", message.destination)
		}
		select {
		case c.data <- message:
		default:
		}
		return
	}
	if newMessage := c.defragger.feed(message); newMessage != nil {
		if c.isServer {
			errors.LogDebug(c.ctx, "TUIC reassembled UDP fragment set on session=", c.sessionID, " size=", len(newMessage.data))
		}
		select {
		case c.data <- newMessage:
		default:
		}
	}
}

func (c *udpPacketConn) writePackets(messages []*udpMessage) error {
	for _, message := range messages {
		if err := c.writePacket(message); err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) writePacket(message *udpMessage) error {
	buffer, err := message.pack()
	if err != nil {
		return err
	}
	if !c.udpStream {
		errors.LogDebug(c.ctx, "TUIC sending UDP datagram session=", c.sessionID, " size=", len(buffer))
		return c.quicConn.SendDatagram(buffer)
	}
	stream, err := c.quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	errors.LogDebug(c.ctx, "TUIC sending UDP stream packet session=", c.sessionID, " size=", len(buffer))
	_, err = stream.Write(buffer)
	closeErr := stream.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		if c.onDestroy != nil {
			c.onDestroy()
		}
	})
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
	if !c.isServer {
		buffer := bytes.NewBuffer(make([]byte, 0, 4))
		buffer.WriteByte(tuicVersion)
		buffer.WriteByte(commandDissociate)
		_ = binary.Write(buffer, binary.BigEndian, c.sessionID)
		stream, openErr := c.quicConn.OpenUniStream()
		if openErr != nil {
			return
		}
		defer stream.Close()
		_, _ = stream.Write(buffer.Bytes())
	}
}

func (c *udpPacketConn) LocalAddr() stdnet.Addr {
	return c.quicConn.LocalAddr()
}

func (c *udpPacketConn) RemoteAddr() stdnet.Addr {
	return c.quicConn.RemoteAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *udpPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

type udpDefragger struct {
	access    sync.Mutex
	packetMap map[uint16]*packetItem
}

func newUDPDefragger() *udpDefragger {
	return &udpDefragger{
		packetMap: make(map[uint16]*packetItem),
	}
}

type packetItem struct {
	messages []*udpMessage
	count    uint8
}

func (d *udpDefragger) feed(m *udpMessage) *udpMessage {
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	item := d.packetMap[m.packetID]
	if item == nil || int(m.fragmentTotal) != len(item.messages) {
		item = &packetItem{
			messages: make([]*udpMessage, m.fragmentTotal),
			count:    1,
		}
		item.messages[m.fragmentID] = m
		d.packetMap[m.packetID] = item
		return nil
	}
	if item.messages[m.fragmentID] != nil {
		return nil
	}
	item.messages[m.fragmentID] = m
	item.count++
	if int(item.count) != len(item.messages) {
		return nil
	}
	delete(d.packetMap, m.packetID)
	newMessage := *item.messages[0]
	var dataLength int
	for _, message := range item.messages {
		dataLength += len(message.data)
	}
	if dataLength == 0 {
		return nil
	}
	newMessage.data = make([]byte, 0, dataLength)
	for _, message := range item.messages {
		newMessage.data = append(newMessage.data, message.data...)
	}
	return &newMessage
}

func readUDPMessage(message *udpMessage, reader io.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &message.sessionID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.packetID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.fragmentTotal); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.fragmentID); err != nil {
		return err
	}
	var dataLength uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLength); err != nil {
		return err
	}
	destination, err := readDestination(reader, xnet.Network_UDP)
	if err != nil {
		return err
	}
	message.destination = destination
	message.data = make([]byte, int(dataLength))
	_, err = io.ReadFull(reader, message.data)
	return err
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.BigEndian, &message.sessionID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.packetID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.fragmentTotal); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.fragmentID); err != nil {
		return err
	}
	var dataLength uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLength); err != nil {
		return err
	}
	destination, err := readDestination(reader, xnet.Network_UDP)
	if err != nil {
		return err
	}
	if reader.Len() != int(dataLength) {
		return io.ErrUnexpectedEOF
	}
	message.destination = destination
	message.data = append([]byte(nil), data[len(data)-reader.Len():]...)
	return nil
}

type packetDeadline struct {
	access sync.Mutex
	timer  *time.Timer
	done   chan struct{}
}

func newPacketDeadline() packetDeadline {
	return packetDeadline{done: make(chan struct{})}
}

func (d *packetDeadline) wait() <-chan struct{} {
	d.access.Lock()
	defer d.access.Unlock()
	return d.done
}

func (d *packetDeadline) set(t time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.done = make(chan struct{})
	if t.IsZero() {
		return
	}
	duration := time.Until(t)
	if duration <= 0 {
		close(d.done)
		return
	}
	done := d.done
	d.timer = time.AfterFunc(duration, func() {
		close(done)
	})
}

type destinationAddr struct {
	destination xnet.Destination
}

func (a destinationAddr) Network() string {
	return a.destination.Network.SystemString()
}

func (a destinationAddr) String() string {
	return a.destination.NetAddr()
}

func destinationFromNetAddr(addr stdnet.Addr, network xnet.Network) (xnet.Destination, error) {
	if addr == nil {
		return xnet.Destination{}, os.ErrInvalid
	}
	switch typedAddr := addr.(type) {
	case destinationAddr:
		destination := typedAddr.destination
		destination.Network = network
		return destination, nil
	case *stdnet.UDPAddr:
		return destinationFromAddress(network, xnet.IPAddress(typedAddr.IP), xnet.Port(typedAddr.Port)), nil
	case *stdnet.TCPAddr:
		return destinationFromAddress(network, xnet.IPAddress(typedAddr.IP), xnet.Port(typedAddr.Port)), nil
	default:
		destination, err := xnet.ParseDestination(network.SystemString() + ":" + addr.String())
		if err != nil {
			return xnet.Destination{}, err
		}
		return destination, nil
	}
}
