package vpnc

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/jackpal/gateway"
	"golang.org/x/sys/unix"
	"sslcon/base"
	"sslcon/session"
)

const (
	rtmVersion              = unix.RTM_VERSION
	routeSocketAlignment    = 4
	routeSocketReceiveSize  = 8 << 20
	routeSocketSendSize     = 4 << 20
	routeSocketAckTimeout   = 10 * time.Second
	routeSocketDrainTimeout = 50 * time.Millisecond
	routeWriteRetries       = 2000
)

// rtMetrics and rtMsghdr mirror struct rt_metrics and struct rt_msghdr from
// macOS' sys/net/route.h. Keep the field order and sizes in sync with the SDK.
type rtMetrics struct {
	Locks    uint32
	Mtu      uint32
	Hopcount uint32
	Expire   int32
	Recvpipe uint32
	Sendpipe uint32
	Ssthresh uint32
	Rtt      uint32
	Rttvar   uint32
	Pksent   uint32
	State    uint32
	Filler   [3]uint32
}

type rtMsghdr struct {
	Msglen  uint16
	Version uint8
	Type    uint8
	Index   uint16
	_       uint16
	Flags   int32
	Addrs   int32
	Pid     int32
	Seq     int32
	Errno   int32
	Use     int32
	Inits   uint32
	Rmx     rtMetrics
}

type darwinRoute struct {
	typ     uint8
	ifidx   int
	dst     net.IP
	mask    net.IPMask
	gateway net.IP
	name    string
}

type routeRequest struct {
	seq   int32
	route darwinRoute
	data  []byte
}

// routeSocketState owns the AF_ROUTE socket. Route socket operations must be
// serialized because both the connection setup and dynamic split tunneling
// can update the kernel from different goroutines.
type routeSocketState struct {
	mu            sync.Mutex
	fd            int
	seq           int32
	localIndex    int
	tunnelIndex   int
	localGateway  net.IP
	tunnelGateway net.IP
	installed     []darwinRoute
}

var (
	VPNAddress  string
	routeSocket = routeSocketState{fd: -1}
)

func ConfigInterface(cSess *session.ConnSession) error {
	VPNAddress = cSess.VPNAddress
	cmdStr1 := fmt.Sprintf("ifconfig %s inet %s %s netmask %s up", cSess.TunName, cSess.VPNAddress, cSess.VPNAddress, "255.255.255.255")
	err := execCmd([]string{cmdStr1})

	return err
}

func SetRoutes(cSess *session.ConnSession) error {
	localIndex, err := interfaceIndex(base.LocalInterface.Name)
	if err != nil {
		return fmt.Errorf("find local interface %q: %w", base.LocalInterface.Name, err)
	}
	tunnelIndex, err := interfaceIndex(cSess.TunName)
	if err != nil {
		return fmt.Errorf("find tunnel interface %q: %w", cSess.TunName, err)
	}
	localGateway, err := parseRouteAddress(base.LocalInterface.Gateway)
	if err != nil {
		return fmt.Errorf("invalid local gateway: %w", err)
	}
	tunnelGateway, err := parseRouteAddress(cSess.VPNAddress)
	if err != nil {
		return fmt.Errorf("invalid VPN address: %w", err)
	}
	serverAddress, err := parseRouteAddress(cSess.ServerAddress)
	if err != nil {
		return fmt.Errorf("invalid VPN server address: %w", err)
	}

	// 到 VPN 服务器的主机路由：重连时可能残留上一会话安装的旧网关路由（异常退出
	// 未清理、或网络切换后网关已变化）。内核 ADD 对已存在的路由返回 EEXIST 并保留
	// 旧条目，导致此后到服务器的 UDP/新建连接报 EADDRNOTAVAIL
	// （macOS: can't assign requested address——正是 DTLS 发送失败的现象）。
	// 因此先删后加，确保使用当前网关（路由不存在时 macOS 返回 ESRCH/no such
	// process，会被 pipeline 容忍，见 pipelineLocked）。
	serverRoute := darwinRoute{
		typ:     unix.RTM_DELETE,
		ifidx:   localIndex,
		dst:     serverAddress,
		gateway: localGateway,
		name:    fmt.Sprintf("VPN server %s (replace)", serverAddress),
	}
	routes := []darwinRoute{serverRoute, {
		typ:     unix.RTM_ADD,
		ifidx:   localIndex,
		dst:     serverAddress,
		gateway: localGateway,
		name:    fmt.Sprintf("VPN server %s", serverAddress),
	}}

	for _, ipMask := range cSess.SplitInclude {
		dst, mask, parseErr := parseRoute(ipMask)
		if parseErr != nil {
			return routingError(ipMask, parseErr)
		}
		routes = append(routes, darwinRoute{
			typ:     unix.RTM_ADD,
			ifidx:   tunnelIndex,
			dst:     dst,
			mask:    mask,
			gateway: tunnelGateway,
			name:    "split include " + ipMask,
		})
	}

	for _, ipMask := range cSess.SplitExclude {
		dst, mask, parseErr := parseRoute(ipMask)
		if parseErr != nil {
			return routingError(ipMask, parseErr)
		}
		routes = append(routes, darwinRoute{
			typ:     unix.RTM_ADD,
			ifidx:   localIndex,
			dst:     dst,
			mask:    mask,
			gateway: localGateway,
			name:    "split exclude " + ipMask,
		})
	}

	if err = routeSocket.add(routes, localIndex, tunnelIndex, localGateway, tunnelGateway); err != nil {
		return err
	}

	// dns
	if len(cSess.DNS) > 0 {
		err = setDNS(cSess)
		if err != nil {
			ResetRoutes(cSess)
			return err
		}
	}

	return err
}

func ResetRoutes(cSess *session.ConnSession) {
	routeSocket.mu.Lock()
	if routeSocket.fd >= 0 {
		routes := make([]darwinRoute, 0, len(routeSocket.installed))
		for _, route := range routeSocket.installed {
			route.typ = unix.RTM_DELETE
			routes = append(routes, route)
		}
		if err := routeSocket.pipelineLocked(routes); err != nil {
			base.Error("reset routes:", err)
		}
	}
	routeSocket.closeLocked()
	routeSocket.mu.Unlock()

	if len(cSess.DNS) > 0 {
		restoreDNS(cSess)
	}
}

func DynamicAddIncludeRoutes(ips []string) {
	routeSocket.addDynamicRoutes(ips, true)
}

func DynamicAddExcludeRoutes(ips []string) {
	routeSocket.addDynamicRoutes(ips, false)
}

func GetLocalInterface() error {
	localInterfaceIP, err := gateway.DiscoverInterface()
	if err != nil {
		return err
	}
	gateway, err := gateway.DiscoverGateway()
	if err != nil {
		return err
	}

	localInterface := net.Interface{}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP.To4()
			if ip.Equal(localInterfaceIP) {
				localInterface = iface
				break
			}
		}
	}
	if localInterface.Name == "" {
		return fmt.Errorf("unable to find interface for local address %s", localInterfaceIP)
	}

	base.LocalInterface.Name = localInterface.Name
	base.LocalInterface.Ip4 = localInterfaceIP.String()
	base.LocalInterface.Gateway = gateway.String()
	base.LocalInterface.Mac = localInterface.HardwareAddr.String()

	base.Info("GetLocalInterface:", fmt.Sprintf("%+v", *base.LocalInterface))

	return nil
}

func routingError(dst string, err error) error {
	return fmt.Errorf("routing error: %s %s", dst, err)
}

func interfaceIndex(name string) (int, error) {
	if name == "" {
		return 0, errors.New("interface name is empty")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	if iface.Index <= 0 {
		return 0, fmt.Errorf("interface %q has invalid index %d", name, iface.Index)
	}
	return iface.Index, nil
}

func parseRouteAddress(value string) (net.IP, error) {
	address := net.ParseIP(strings.TrimSpace(value))
	if address == nil {
		return nil, fmt.Errorf("invalid IP address %q", value)
	}
	if ipv4 := address.To4(); ipv4 != nil {
		return cloneIP(ipv4), nil
	}
	return cloneIP(address.To16()), nil
}

// parseRoute accepts both the masks sent by AnyConnect (for example
// 10.0.0.0/255.255.0.0) and ordinary CIDR prefixes.
func parseRoute(value string) (net.IP, net.IPMask, error) {
	parts := strings.SplitN(strings.TrimSpace(value), "/", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("route %q has no mask", value)
	}

	address, err := parseRouteAddress(parts[0])
	if err != nil {
		return nil, nil, err
	}

	maskText := strings.TrimSpace(parts[1])
	if strings.Contains(maskText, ".") {
		if address.To4() == nil {
			return nil, nil, fmt.Errorf("IPv4 mask on non-IPv4 route %q", value)
		}
		maskIP := net.ParseIP(maskText).To4()
		if maskIP == nil {
			return nil, nil, fmt.Errorf("invalid IPv4 mask %q", maskText)
		}
		mask := net.IPMask(maskIP)
		ones, bits := mask.Size()
		if bits != 32 || ones < 0 {
			return nil, nil, fmt.Errorf("non-contiguous IPv4 mask %q", maskText)
		}
		return address.To4().Mask(mask), mask, nil
	}

	prefix, err := strconv.Atoi(maskText)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid prefix %q", maskText)
	}
	bits := 128
	if address.To4() != nil {
		bits = 32
		address = address.To4()
	}
	if prefix < 0 || prefix > bits {
		return nil, nil, fmt.Errorf("prefix %d is outside [0,%d]", prefix, bits)
	}
	mask := net.CIDRMask(prefix, bits)
	return address.Mask(mask), mask, nil
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func routeHeaderSize() int {
	return int(unsafe.Sizeof(rtMsghdr{}))
}

func routeSockaddrSize(size int) int {
	return (size + routeSocketAlignment - 1) &^ (routeSocketAlignment - 1)
}

func routeSockaddr(ip net.IP) (int, []byte, error) {
	if ipv4 := ip.To4(); ipv4 != nil {
		sa := unix.RawSockaddrInet4{
			Len:    uint8(unsafe.Sizeof(unix.RawSockaddrInet4{})),
			Family: uint8(unix.AF_INET),
		}
		copy(sa.Addr[:], ipv4)
		data := make([]byte, int(unsafe.Sizeof(sa)))
		copy(data, unsafe.Slice((*byte)(unsafe.Pointer(&sa)), len(data)))
		return unix.AF_INET, data, nil
	}

	if ipv6 := ip.To16(); ipv6 != nil {
		sa := unix.RawSockaddrInet6{
			Len:    uint8(unsafe.Sizeof(unix.RawSockaddrInet6{})),
			Family: uint8(unix.AF_INET6),
		}
		copy(sa.Addr[:], ipv6)
		data := make([]byte, int(unsafe.Sizeof(sa)))
		copy(data, unsafe.Slice((*byte)(unsafe.Pointer(&sa)), len(data)))
		return unix.AF_INET6, data, nil
	}

	return 0, nil, errors.New("invalid route address")
}

func routeNetmask(family int, mask net.IPMask) ([]byte, error) {
	if family == unix.AF_INET {
		if len(mask) != net.IPv4len {
			return nil, errors.New("invalid IPv4 route mask")
		}
		sa := unix.RawSockaddrInet4{
			Len:    uint8(unsafe.Sizeof(unix.RawSockaddrInet4{})),
			Family: uint8(unix.AF_INET),
		}
		copy(sa.Addr[:], mask)
		data := make([]byte, int(unsafe.Sizeof(sa)))
		copy(data, unsafe.Slice((*byte)(unsafe.Pointer(&sa)), len(data)))
		return data, nil
	}

	if family == unix.AF_INET6 {
		if len(mask) != net.IPv6len {
			return nil, errors.New("invalid IPv6 route mask")
		}
		sa := unix.RawSockaddrInet6{
			Len:    uint8(unsafe.Sizeof(unix.RawSockaddrInet6{})),
			Family: uint8(unix.AF_INET6),
		}
		copy(sa.Addr[:], mask)
		data := make([]byte, int(unsafe.Sizeof(sa)))
		copy(data, unsafe.Slice((*byte)(unsafe.Pointer(&sa)), len(data)))
		return data, nil
	}

	return nil, fmt.Errorf("unsupported route address family %d", family)
}

func appendRouteSockaddr(dst, sockaddr []byte) []byte {
	dst = append(dst, sockaddr...)
	padding := routeSockaddrSize(len(sockaddr)) - len(sockaddr)
	return append(dst, make([]byte, padding)...)
}

func buildRtMsg(typ uint8, seq int32, ifidx int, dst net.IP, mask net.IPMask, gateway net.IP) ([]byte, error) {
	if ifidx <= 0 {
		return nil, fmt.Errorf("invalid interface index %d", ifidx)
	}
	dstFamily, dstSockaddr, err := routeSockaddr(dst)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	gatewayFamily, gatewaySockaddr, err := routeSockaddr(gateway)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	if dstFamily != gatewayFamily {
		return nil, fmt.Errorf("destination family %d differs from gateway family %d", dstFamily, gatewayFamily)
	}

	flags := int32(unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC)
	addrs := int32(unix.RTA_DST | unix.RTA_GATEWAY)
	var maskSockaddr []byte
	if mask == nil {
		flags |= unix.RTF_HOST
	} else {
		ones, bits := mask.Size()
		if bits == 0 || (bits != 32 && bits != 128) || ones < 0 {
			return nil, errors.New("invalid route mask")
		}
		if ones == bits {
			flags |= unix.RTF_HOST
		} else {
			maskSockaddr, err = routeNetmask(dstFamily, mask)
			if err != nil {
				return nil, err
			}
			addrs |= unix.RTA_NETMASK
		}
	}

	addresses := make([]byte, 0, routeSockaddrSize(len(dstSockaddr))+routeSockaddrSize(len(gatewaySockaddr))+routeSockaddrSize(len(maskSockaddr)))
	addresses = appendRouteSockaddr(addresses, dstSockaddr)
	addresses = appendRouteSockaddr(addresses, gatewaySockaddr)
	if maskSockaddr != nil {
		addresses = appendRouteSockaddr(addresses, maskSockaddr)
	}

	messageLength := routeHeaderSize() + len(addresses)
	if messageLength > int(^uint16(0)) {
		return nil, fmt.Errorf("route message is too large: %d", messageLength)
	}
	hdr := rtMsghdr{
		Msglen:  uint16(messageLength),
		Version: rtmVersion,
		Type:    typ,
		Index:   uint16(ifidx),
		Flags:   flags,
		Addrs:   addrs,
		Pid:     int32(os.Getpid()),
		Seq:     seq,
	}

	message := make([]byte, messageLength)
	copy(message, unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), routeHeaderSize()))
	copy(message[routeHeaderSize():], addresses)
	return message, nil
}

func decodeRtMsg(data []byte) (rtMsghdr, bool) {
	var hdr rtMsghdr
	if len(data) < routeHeaderSize() {
		return hdr, false
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), routeHeaderSize()), data[:routeHeaderSize()])
	return hdr, true
}

func (r *routeSocketState) add(routes []darwinRoute, localIndex, tunnelIndex int, localGateway, tunnelGateway net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.openLocked(localIndex, tunnelIndex, localGateway, tunnelGateway); err != nil {
		return err
	}
	return r.pipelineLocked(routes)
}

func (r *routeSocketState) addDynamicRoutes(ips []string, throughTunnel bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.fd < 0 {
		return
	}
	ifidx := r.localIndex
	gateway := r.localGateway
	name := "dynamic split exclude "
	if throughTunnel {
		ifidx = r.tunnelIndex
		gateway = r.tunnelGateway
		name = "dynamic split include "
	}

	routes := make([]darwinRoute, 0, len(ips))
	for _, value := range ips {
		dst, err := parseRouteAddress(value)
		if err != nil {
			base.Error(name+value+":", err)
			continue
		}
		routes = append(routes, darwinRoute{
			typ:     unix.RTM_ADD,
			ifidx:   ifidx,
			dst:     dst,
			gateway: cloneIP(gateway),
			name:    name + value,
		})
	}
	if err := r.pipelineLocked(routes); err != nil {
		base.Error("add dynamic routes:", err)
	} else if len(routes) > 0 {
		base.Debug("dynamic routes added:", len(routes))
	}
}

func (r *routeSocketState) openLocked(localIndex, tunnelIndex int, localGateway, tunnelGateway net.IP) error {
	if r.fd >= 0 {
		return nil
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("create AF_ROUTE socket: %w", err)
	}
	unix.CloseOnExec(fd)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(fd)
		}
	}()

	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, routeSocketReceiveSize); err != nil {
		return fmt.Errorf("set AF_ROUTE receive buffer: %w", err)
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, routeSocketSendSize); err != nil {
		return fmt.Errorf("set AF_ROUTE send buffer: %w", err)
	}
	if err = setRouteSocketTimeout(fd, routeSocketAckTimeout); err != nil {
		return fmt.Errorf("set AF_ROUTE receive timeout: %w", err)
	}

	r.fd = fd
	r.localIndex = localIndex
	r.tunnelIndex = tunnelIndex
	r.localGateway = cloneIP(localGateway)
	r.tunnelGateway = cloneIP(tunnelGateway)
	if err = r.drainLocked(); err != nil {
		r.fd = -1
		return fmt.Errorf("drain AF_ROUTE socket: %w", err)
	}
	closeOnError = false
	return nil
}

func setRouteSocketTimeout(fd int, timeout time.Duration) error {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

func (r *routeSocketState) drainLocked() error {
	if r.fd < 0 {
		return nil
	}
	if err := setRouteSocketTimeout(r.fd, routeSocketDrainTimeout); err != nil {
		return err
	}
	defer func() {
		_ = setRouteSocketTimeout(r.fd, routeSocketAckTimeout)
	}()

	buffer := make([]byte, 64*1024)
	for {
		_, err := unix.Read(r.fd, buffer)
		if err == nil {
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return nil
		}
		return err
	}
}

func (r *routeSocketState) pipelineLocked(routes []darwinRoute) error {
	if len(routes) == 0 {
		return nil
	}
	if r.fd < 0 {
		return errors.New("AF_ROUTE socket is not open")
	}
	if err := r.drainLocked(); err != nil {
		return err
	}

	requests := make([]routeRequest, 0, len(routes))
	for _, route := range routes {
		seq := r.nextSequence()
		data, err := buildRtMsg(route.typ, seq, route.ifidx, route.dst, route.mask, route.gateway)
		if err != nil {
			return fmt.Errorf("%s: %w", route.name, err)
		}
		requests = append(requests, routeRequest{seq: seq, route: route, data: data})
	}

	// 只跟踪真正写入内核的请求：跳过 EEXIST 的路由（如本机局域网路由已存在），
	// 否则收集 ACK 时会一直等待一个永远不会到达的应答
	written := make([]routeRequest, 0, len(requests))
	for index, request := range requests {
		if err := r.writeWithRetry(request.data); err != nil {
			if request.route.typ == unix.RTM_ADD && errors.Is(err, unix.EEXIST) {
				// 路由已存在（如本机局域网 192.168.199.0/24），无需重复添加，
				// 也绝不能记入 installed，否则断开时会误删原有路由
				base.Debug("route already exists, skip:", request.route.name)
				continue
			}
			if request.route.typ == unix.RTM_DELETE && (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)) {
				// 删除不存在的路由是正常情况（macOS 直接以 ESRCH/no such process
				// 或 ENOENT 从 write 返回，而非通过 ACK），跳过即可：
				// SetRoutes 对 VPN 服务器主机路由先删后加，多数时候并没有旧路由可删
				base.Debug("route not found, skip delete:", request.route.name)
				continue
			}
			if len(written) > 0 {
				results, collectErr := r.collectAcksLocked(written)
				r.rollbackSuccessfulAddsLocked(written, results)
				if collectErr != nil {
					return fmt.Errorf("write route %d (%s): %w; collecting previously sent ACKs: %v", index, request.route.name, err, collectErr)
				}
			}
			return fmt.Errorf("write route %d (%s): %w", index, request.route.name, err)
		}
		written = append(written, request)
	}

	results, err := r.collectAcksLocked(written)
	r.applyResultsLocked(written, results)
	if err != nil {
		r.rollbackSuccessfulAddsLocked(written, results)
		return err
	}
	var firstRouteError error
	for _, request := range written {
		routeErr := results[request.seq]
		if routeErr == nil {
			continue
		}
		// 内核也可能通过 ACK 报告 EEXIST，同样视为成功
		if request.route.typ == unix.RTM_ADD && errors.Is(routeErr, unix.EEXIST) {
			continue
		}
		// 删除不存在的路由（ENOENT/ESRCH）视为成功：SetRoutes 对 VPN 服务器主机路由
		// 先删后加，路由不存在时删除会返回 ENOENT（或 ESRCH），不应中断后续添加
		if request.route.typ == unix.RTM_DELETE && (errors.Is(routeErr, unix.ENOENT) || errors.Is(routeErr, unix.ESRCH)) {
			continue
		}
		if firstRouteError == nil {
			firstRouteError = fmt.Errorf("%s: %w", request.route.name, routeErr)
		}
	}
	if firstRouteError != nil {
		r.rollbackSuccessfulAddsLocked(written, results)
		return firstRouteError
	}
	return nil
}

func (r *routeSocketState) applyResultsLocked(requests []routeRequest, results map[int32]error) {
	for _, request := range requests {
		if err, ok := results[request.seq]; !ok || err != nil {
			continue
		}
		switch request.route.typ {
		case unix.RTM_ADD:
			r.installed = append(r.installed, request.route)
		case unix.RTM_DELETE:
			r.removeInstalledLocked(request.route)
		}
	}
}

func (r *routeSocketState) removeInstalledLocked(route darwinRoute) {
	for index := len(r.installed) - 1; index >= 0; index-- {
		if sameRoute(r.installed[index], route) {
			r.installed = append(r.installed[:index], r.installed[index+1:]...)
			return
		}
	}
}

func sameRoute(left, right darwinRoute) bool {
	return left.ifidx == right.ifidx &&
		left.dst.Equal(right.dst) &&
		bytes.Equal(left.mask, right.mask) &&
		left.gateway.Equal(right.gateway)
}

func (r *routeSocketState) rollbackSuccessfulAddsLocked(requests []routeRequest, results map[int32]error) {
	rollback := make([]darwinRoute, 0, len(requests))
	for _, request := range requests {
		if request.route.typ != unix.RTM_ADD {
			continue
		}
		if err, ok := results[request.seq]; !ok || err != nil {
			continue
		}

		route := request.route
		route.typ = unix.RTM_DELETE
		rollback = append(rollback, route)
	}
	if len(rollback) == 0 {
		return
	}
	if err := r.pipelineLocked(rollback); err != nil {
		base.Error("rollback routes:", err)
	}
}

func (r *routeSocketState) nextSequence() int32 {
	r.seq++
	if r.seq == 0 {
		r.seq = 1
	}
	return r.seq
}

func (r *routeSocketState) writeWithRetry(data []byte) error {
	for attempt := 0; ; attempt++ {
		written, err := unix.Write(r.fd, data)
		if err == nil {
			if written != len(data) {
				return fmt.Errorf("short write: %d/%d bytes", written, len(data))
			}
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		if attempt >= routeWriteRetries {
			return fmt.Errorf("after %d retries: %w", attempt, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *routeSocketState) collectAcksLocked(requests []routeRequest) (map[int32]error, error) {
	wanted := make(map[int32]struct{}, len(requests))
	for _, request := range requests {
		wanted[request.seq] = struct{}{}
	}
	results := make(map[int32]error, len(requests))
	buffer := make([]byte, 64*1024)

	for len(results) < len(wanted) {
		n, err := unix.Read(r.fd, buffer)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			missing := len(wanted) - len(results)
			return results, fmt.Errorf("collect AF_ROUTE ACKs: received %d/%d, %d missing: %w", len(results), len(wanted), missing, err)
		}
		if n < routeHeaderSize() {
			continue
		}

		// AF_ROUTE normally returns one record per read. Walk the records as
		// well, because a socket may provide multiple notifications at once.
		for offset := 0; offset+routeHeaderSize() <= n; {
			hdr, ok := decodeRtMsg(buffer[offset:n])
			if !ok || int(hdr.Msglen) < routeHeaderSize() {
				break
			}
			messageLength := int(hdr.Msglen)
			if offset+messageLength > n {
				break
			}
			if _, ok := wanted[hdr.Seq]; ok {
				if _, done := results[hdr.Seq]; !done {
					if hdr.Errno == 0 {
						results[hdr.Seq] = nil
					} else {
						// %w 包装 errno，便于调用方用 errors.Is 识别 EEXIST 等场景
						results[hdr.Seq] = fmt.Errorf("kernel errno=%d (%s): %w", hdr.Errno, unix.Errno(hdr.Errno), unix.Errno(hdr.Errno))
					}
				}
			}
			offset += messageLength
		}
	}

	return results, nil
}

func (r *routeSocketState) closeLocked() {
	if r.fd >= 0 {
		_ = unix.Close(r.fd)
	}
	r.fd = -1
	r.localIndex = 0
	r.tunnelIndex = 0
	r.localGateway = nil
	r.tunnelGateway = nil
	r.installed = nil
}

func execCmd(cmdStrs []string) error {
	for _, cmdStr := range cmdStrs {
		cmd := exec.Command("sh", "-c", cmdStr)
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s %s", err, cmd.String(), string(stdoutStderr))
		}
	}
	return nil
}

func setDNS(cSess *session.ConnSession) error {

	if len(cSess.DynamicSplitIncludeDomains) > 0 {
		DynamicAddIncludeRoutes(cSess.DNS)
	}

	var override string
	// 如果包含路由为空必为全局路由，如果使用包含域名，则包含路由必须填写一个，如 dns 地址
	if len(cSess.SplitInclude) == 0 {
		override = "d.add OverridePrimary # 1"
	}

	command := fmt.Sprintf(`
		open
		d.init
		d.add ServerAddresses * %s
        d.add SearchOrder 1
        d.add SupplementalMatchDomains * ""
		set State:/Network/Service/%s/DNS

		d.init
		d.add Router %s
		d.add Addresses * %s
		d.add InterfaceName %s
        %s
		set State:/Network/Service/%s/IPv4
		close
	`, strings.Join(cSess.DNS, " "), cSess.TunName, cSess.VPNAddress, cSess.VPNAddress, cSess.TunName, override, cSess.TunName)

	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(command)

	// 执行命令并获取输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		base.Error(err, output)
	}
	return err
}

func restoreDNS(cSess *session.ConnSession) {
	command := fmt.Sprintf(`
        open
        remove State:/Network/Service/%s/IPv4
        remove State:/Network/Service/%s/DNS
        close
	`, cSess.TunName, cSess.TunName)

	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(command)

	// 执行命令并获取输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		base.Error(err, output)
	}
}
