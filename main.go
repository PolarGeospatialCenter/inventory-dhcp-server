package main

import (
	"fmt"
	"net"

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
	InventoryCliConfig string
	NextServer         string // The NextServer option to pass to clients
	Filename           string // The Filename option to pass to clients
}

type DHCPServer struct {
	Inventory inventoryNodeGetter
	Config    DHCPServerConfig
}

type inventoryNodeGetter interface {
	GetByMac(mac net.HardwareAddr) (*types.InventoryNode, error)
}

func apiConnect() (*client.InventoryApi, error) {
	return client.NewInventoryApiDefaultConfig(viper.GetString("InventoryCliConfig"))
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

	modifiers = append(modifiers, d.globalModifiers()...)

	return modifiers, err

}

func (d *DHCPServer) createOfferPacket(m *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {

	// Get Node from API
	inventoryNode, err := d.Inventory.GetByMac(m.ClientHWAddr)
	if err != nil {
		return nil, err
	}

	// Get Node Specific Modifiers
	modifiers, err := d.modifiersFromInventoryNode(m.ClientHWAddr, inventoryNode)
	if err != nil {
		return nil, err
	}

	// Get Global Modifiers

	// Append Offer Message Type
	modifiers = append(modifiers, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))

	return dhcpv4.NewReplyFromRequest(m, modifiers...)
}

//Verifies that a packet has the matching info in the inventory API
func (d *DHCPServer) validPacket(m *dhcpv4.DHCPv4) (bool, error) {
	// Get Packet that should of been offered
	expectedPacket, err := d.createOfferPacket(m)
	if err != nil {
		return false, fmt.Errorf("error createing expected packet: %v", err)
	}

	if m.YourIPAddr.String() == expectedPacket.YourIPAddr.String() {
		return true, nil
	}
	return false, nil
}

func (d *DHCPServer) handler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	// Setup our Reply
	var reply *dhcpv4.DHCPv4
	var err error

	switch m.MessageType() {

	case dhcpv4.MessageTypeDiscover:

		reply, err = d.createOfferPacket(m)
		if err != nil {
			log.Errorf("error creating offer packet for client %s: %v", m.ClientHWAddr, err)
			return
		}

	case dhcpv4.MessageTypeRequest:

		packetValid, err := d.validPacket(m)
		if err != nil {
			log.Errorf("error validating request packet for client %s: %v", m.ClientHWAddr, err)
			return
		}

		if packetValid {
			reply, _ = dhcpv4.NewReplyFromRequest(m,
				dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
		} else {
			reply, _ = dhcpv4.NewReplyFromRequest(m,
				dhcpv4.WithMessageType(dhcpv4.MessageTypeNak))
		}
	}

	if reply != nil {
		log.Infof("Sending DHCP reply to %s", m.ClientHWAddr)
		conn.WriteTo(m.ToBytes(), peer)
	}
}

func setDefaultConfig() {
	viper.SetDefault("ListenIP", "0.0.0.0")
	viper.SetDefault("InventoryCliConfig", "")
	viper.SetDefault("IPNet", "")
}

func main() {

	srv := &DHCPServer{}

	//  Setup Config
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/inventory-dhcp-server")
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("inventory_dhcp")
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

	log.Infof("Config:\n %+v", srv.Config)

	listenAddr := net.UDPAddr{
		IP:   net.ParseIP(srv.Config.ListenIP),
		Port: dhcpv4.ServerPort,
	}

	client, err := apiConnect()
	if err != nil {
		log.Panic(fmt.Errorf("cannot connect to inventory api: %v", err))
	}

	srv.Inventory = client.NodeConfig()

	server := server4.NewServer(listenAddr, srv.handler)

	defer server.Close()
	if err := server.ActivateAndServe(); err != nil {
		log.Panic(err)
	}
}
