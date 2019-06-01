package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	beeline "github.com/honeycombio/beeline-go"
	"github.com/honeycombio/beeline-go/trace"

	"github.com/PolarGeospatialCenter/inventory-client/pkg/api/client"
	"github.com/PolarGeospatialCenter/inventory/pkg/inventory/types"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type DHCPServerConfig struct {
	ListenIP           string // The IP The server listens on
	IPNet              string // The subnet this server is giving out addresses on
	NextServer         string // The NextServer option to pass to clients
	Filename           string // The Filename option to pass to clients
	ServerIdentifier   string // The Server Identifier, should be the IP of the network interface packets come in on.
	InventoryAPIConfig *client.InventoryApiConfig
	HoneycombWriteKey  string
	HoneycombDataset   string
}

type DHCPServer struct {
	Inventory inventoryNodeGetter
	Config    DHCPServerConfig
}

type inventoryNodeGetter interface {
	GetByMac(mac net.HardwareAddr) (*types.InventoryNode, error)
}

func apiConnect(ctx context.Context, cfg *client.InventoryApiConfig) (*client.InventoryApi, error) {
	_, span := trace.GetSpanFromContext(ctx).CreateChild(ctx)
	span.AddField("name", "apiConnect")
	defer span.Send()

	if cfg != nil {
		return client.NewInventoryApiFromConfig(cfg)
	}

	return client.NewInventoryApiDefaultConfig("")
}

func getNetworkMatchingMacFromInventoryNode(mac net.HardwareAddr, node *types.InventoryNode) (*types.NICInstance, error) {

	for _, net := range node.Networks {
		if net.NIC.MAC.String() == mac.String() {
			return net, nil
		}
	}
	// No network found for this mac, this shouldn't happen
	return nil, fmt.Errorf("no network found matching mac address %s", mac)
}

func modifiersFromNicConfig(nicConfig *types.NicConfig, ipNet *net.IPNet) ([]dhcpv4.Modifier, error) {
	result := []dhcpv4.Modifier{}

	if len(nicConfig.IP) < 1 {
		return result, fmt.Errorf("no IP found in nicConfig")
	}

	for index, ip := range nicConfig.IP {
		inventoryIPParsed, inventoryIPNetParsed, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("error parsing IP in inventory %s: %v", ip, err)
		}

		if ipNet.Contains(inventoryIPParsed) {

			// Append our IP
			result = append(result,
				dhcpv4.WithYourIP(inventoryIPParsed),
				dhcpv4.WithNetmask(inventoryIPNetParsed.Mask))

			// Append Gateway at our IP index if it exists
			gateway := net.ParseIP(nicConfig.Gateway[index])
			if gateway != nil {
				result = append(result,
					dhcpv4.WithRouter(gateway))
			}

			// Append DNS Servers if they exist
			dnsServers := []net.IP{}
			for _, dnsServer := range nicConfig.DNS {
				dnsServers = append(dnsServers, net.ParseIP(dnsServer))
			}
			result = append(result,
				dhcpv4.WithDNS(dnsServers...))
		}
	}

	return result, nil
}

func withRelayAgentInfo(o *dhcpv4.RelayOptions) dhcpv4.Modifier {
	options := []dhcpv4.Option{}
	log.Printf("options: %v", options)
	for code, value := range o.Options {
		options = append(options, dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(code), value))
	}
	return dhcpv4.WithOption(dhcpv4.OptRelayAgentInfo(options...))
}

func (d *DHCPServer) globalModifiers() []dhcpv4.Modifier {
	result := []dhcpv4.Modifier{}

	if d.Config.NextServer != "" {
		result = append(result,
			dhcpv4.WithOption(dhcpv4.OptTFTPServerName(d.Config.NextServer)))
	}

	if d.Config.Filename != "" {
		result = append(result,
			dhcpv4.WithOption(dhcpv4.OptBootFileName(d.Config.Filename)))
	}

	result = append(result,
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP(d.Config.ServerIdentifier))))

	result = append(result,
		dhcpv4.WithServerIP(net.ParseIP(d.Config.NextServer)))

	result = append(result,
		dhcpv4.WithLeaseTime(3600))

	return result
}

func (d *DHCPServer) modifiersFromInventoryNode(mac net.HardwareAddr, inventoryNode *types.InventoryNode) ([]dhcpv4.Modifier, error) {

	// The network the user provided in config to match against
	_, ipNet, err := net.ParseCIDR(d.Config.IPNet)
	if err != nil {
		return nil, fmt.Errorf("error parsing user provided IPNet %s: %v", d.Config.IPNet, err)
	}

	nicInstance, err := getNetworkMatchingMacFromInventoryNode(mac, inventoryNode)
	if err != nil {
		return nil, err
	}

	modifiers, err := modifiersFromNicConfig(&nicInstance.Config, ipNet)
	if err != nil {
		return nil, err
	}

	if inventoryNode.Hostname != "" {
		modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptHostName(inventoryNode.Hostname)))
	}

	// Append whatever global modifiers we have
	modifiers = append(modifiers, d.globalModifiers()...)

	return modifiers, err

}

func (d *DHCPServer) createOfferPacket(ctx context.Context, m *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	_, span := trace.GetSpanFromContext(ctx).CreateChild(ctx)
	defer span.Send()
	span.AddField("name", "createOfferPacket")

	// Get Node from API
	inventoryNode, err := d.Inventory.GetByMac(m.ClientHWAddr)
	if err != nil {
		span.AddField("error", err.Error())
		return nil, err
	}
	span.AddField("node_id", inventoryNode.ID())

	// Get Node Specific Modifiers
	modifiers, err := d.modifiersFromInventoryNode(m.ClientHWAddr, inventoryNode)
	if err != nil {
		span.AddField("error", err.Error())
		return nil, err
	}

	// Append Offer Message Type
	modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))

	relayInfo := m.RelayAgentInfo()
	if relayInfo != nil {
		modifiers = append(modifiers, withRelayAgentInfo(relayInfo))
	}

	return dhcpv4.NewReplyFromRequest(m, modifiers...)
}

func (d *DHCPServer) createAckNakPacket(ctx context.Context, m *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	_, span := trace.GetSpanFromContext(ctx).CreateChild(ctx)
	defer span.Send()
	span.AddField("name", "createAckNakPacket")

	// Get Node from API
	inventoryNode, err := d.Inventory.GetByMac(m.ClientHWAddr)
	if err != nil {
		span.AddField("error", err.Error())
		return nil, err
	}
	span.AddField("node_id", inventoryNode.ID())

	// Get Node Specific Modifiers
	modifiers, err := d.modifiersFromInventoryNode(m.ClientHWAddr, inventoryNode)
	if err != nil {
		span.AddField("error", err.Error())
		return nil, err
	}

	expectedPacket, err := dhcpv4.NewReplyFromRequest(m, modifiers...)
	if err != nil {
		span.AddField("error", err.Error())
		return nil, err
	}

	// Check if packet is valid
	packetValid, err := d.validPacket(expectedPacket, m)
	if err != nil {
		span.AddField("error", err.Error())
		return nil, fmt.Errorf("error validating request packet for client %s: %v", m.ClientHWAddr, err)
	}

	if packetValid {
		modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	} else {
		modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeNak))
	}

	relayInfo := m.RelayAgentInfo()
	if relayInfo != nil {
		modifiers = append(modifiers, withRelayAgentInfo(relayInfo))
	}

	return dhcpv4.NewReplyFromRequest(m, modifiers...)
}

//Verifies that a packet has the matching info in the inventory API
func (d *DHCPServer) validPacket(expectedPacket, packet *dhcpv4.DHCPv4) (bool, error) {

	if packet.RequestedIPAddress().String() == expectedPacket.YourIPAddr.String() {
		return true, nil
	}
	return false, nil
}

func (d *DHCPServer) handler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	// Setup our Reply
	var reply *dhcpv4.DHCPv4
	var err error

	ctx, tr := trace.NewTrace(context.Background(), "")
	defer tr.Send()
	span := tr.GetRootSpan()
	span.AddField("name", "handler")
	if m.ClientHWAddr != nil {
		span.AddField("mac", m.ClientHWAddr.String())
	}
	span.AddField("request_packet_type", m.MessageType())
	span.AddField("request.giaddr", m.GatewayIPAddr)
	span.AddField("request.summary", m.Summary())
	span.AddField("request.transaction_id", m.TransactionID.String())
	span.AddField("request.ciaddr", m.ClientIPAddr.String())

	log.Infof("Got packet from peer %s: %s", peer, m.Summary())

	switch m.MessageType() {

	case dhcpv4.MessageTypeDiscover:
		// If we get a discover packet, create an offer for its mac address
		log.Infof("Got discover message for: %s", m.ClientHWAddr)

		reply, err = d.createOfferPacket(ctx, m)
		if err != nil {
			span.AddField("error", err.Error())
			log.Errorf("error creating offer packet for client %s: %v", m.ClientHWAddr, err)
			return
		}

		// peer, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:68", reply.YourIPAddr.String()))
		// if err != nil {
		// 	log.Errorf("error setting peer address: %v", err)
		// }

	case dhcpv4.MessageTypeRequest:
		// If we get a request packet, verify that the IP matches what is in inventory and send the correct response.
		log.Infof("Got request message for: %s", m.ClientHWAddr)

		reply, err = d.createAckNakPacket(ctx, m)
		if err != nil {
			span.AddField("error", err.Error())
			log.Errorf("error creating Ack or Nak packet for client %s: %v", m.ClientHWAddr, err)
			return
		}
	}

	if reply != nil {
		span.AddField("reply.summary", reply.Summary())
		span.AddField("reply.yiaddr", reply.YourIPAddr.String())
		log.Infof("Sending DHCP reply for %s to peer: %s", reply.ClientHWAddr, peer)

		// Convert the packet to bytes and send it to our peer.
		if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
			span.AddField("error", err.Error())
			log.Errorf("Cannot reply to client %s: %v", reply.ClientHWAddr, err)
		}

		log.Infof("Replied to %s peer: %s", reply.ClientHWAddr, peer)
		log.Infof("Packet Sent to peer: %s", reply.Summary())
	}
}

func setDefaultConfig() {
	viper.SetDefault("listenip", "0.0.0.0")
	viper.SetDefault("ipnet", "192.168.1.1/24")
	viper.BindEnv("filename")
	viper.BindEnv("nextserver")
	viper.BindEnv("honeycombwritekey")
	viper.BindEnv("honeycombdataset")
	viper.BindEnv("inventoryapiconfig.baseurl")
	viper.BindEnv("inventoryapiconfig.aws.region")
	viper.BindEnv("inventoryapiconfig.aws.vault_role")
	viper.BindEnv("inventoryapiconfig.aws.profile")
	viper.BindEnv("serveridentifier")
}

func main() {

	srv := &DHCPServer{}

	//  Setup Config
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/inventory-dhcp-server")
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("inventory_dhcp")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	setDefaultConfig()

	err := viper.ReadInConfig()
	switch err.(type) {
	case viper.ConfigFileNotFoundError:
		log.Infof("config file not found, using defaults")
	case nil:
		break
	default:
		log.Panic(fmt.Errorf("fatal error config file: %v", err))
	}

	viper.AutomaticEnv()

	err = viper.Unmarshal(&srv.Config)
	if err != nil {
		log.Panic(fmt.Errorf("fatal error unmarshaling config file: %v", err))
	}

	//	log.Infof("%+v", viper.AllSettings())
	log.Infof("Server Config:\n %+v", srv.Config)
	log.Infof("API Config:\n %+v", srv.Config.InventoryAPIConfig)

	beeline.Init(beeline.Config{
		WriteKey: srv.Config.HoneycombWriteKey,
		Dataset:  srv.Config.HoneycombDataset,
		Debug:    true,
	})
	defer beeline.Close()

	ctx, tr := trace.NewTrace(context.Background(), "")
	tr.GetRootSpan().AddField("name", "dhcp_server_startup")

	listenAddr := &net.UDPAddr{
		IP:   net.ParseIP(srv.Config.ListenIP),
		Port: dhcpv4.ServerPort,
	}

	client, err := apiConnect(ctx, srv.Config.InventoryAPIConfig)
	if err != nil {
		log.Panic(fmt.Errorf("cannot connect to inventory api: %v", err))
	}

	srv.Inventory = client.NodeConfig()

	tr.Send()
	server, err := server4.NewServer(listenAddr, srv.handler)

	if err != nil {
		log.Panic(err)
	}

	if err := server.Serve(); err != nil {
		log.Panic(err)
	}
}
