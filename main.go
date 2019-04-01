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

var conf = map[string]string{
	"networkName": "provisioning",
	//"subnet cidr"
	//"listen address"
	//"ntp?"
	//"search domains"
	//"Next server"
	//"filename"
	//"inventory config path"
}

type DHCPServer struct {
	Inventory inventoryNodeGetter
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

func dhcpModifiersFromNicConfig(nicConfig *types.NicConfig) ([]dhcpv4.Modifier, error) {
	result := []dhcpv4.Modifier{}

	if len(nicConfig.IP) < 1 {
		return result, fmt.Errorf("no IP found in nicConfig")
	}

	// Append the IP information from the first IP in the network
	ip, ipNet, err := net.ParseCIDR(nicConfig.IP[0])
	if err != nil {
		return nil, err
	}
	result = append(result,
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithNetmask(ipNet.Mask))

	// Append Gateway if it exists
	gateway := net.ParseIP(nicConfig.Gateway[0])
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

	return result, nil
}

func (d *DHCPServer) modifiersFromInventoryNode(mac net.HardwareAddr, inventoryNode *types.InventoryNode) ([]dhcpv4.Modifier, error) {

	nicInstance, err := getNetworkMatchingMacFromInventoryNode(mac, inventoryNode)
	if err != nil {
		return nil, err
	}

	modifiers, err := dhcpModifiersFromNicConfig(&nicInstance.Config)
	if err != nil {
		return nil, err
	}

	if inventoryNode.Hostname != "" {
		modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptHostName(inventoryNode.Hostname)))
	}

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
		// ip, _ := lookupIPFromMac(m.ClientHWAddr, c)
		// // If we don't have an IP for this mac address OR our IP is different, reject.
		// if ip == nil || !ip.Equal(m.YourIPAddr) {
		// 	reply, _ = dhcpv4.NewReplyFromRequest(m,
		// 		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak))
		// } else {
		reply, _ = dhcpv4.NewReplyFromRequest(m,
			dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
		// }
	}

	if reply != nil {
		log.Print(reply.Summary())
		//conn.WriteTo(m.ToBytes(), peer)
	}
}

func setDefaultConfig() {
	viper.SetDefault("ListenIP", "0.0.0.0")
	viper.SetDefault("InventoryCliConfig", "")

}

func main() {
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

	laddr := net.UDPAddr{
		IP:   net.ParseIP(viper.GetString("ListenIP")),
		Port: dhcpv4.ServerPort,
	}

	client, err := apiConnect()
	if err != nil {
		log.Panic(fmt.Errorf("cannot connect to inventory api: %v", err))
	}

	srv := &DHCPServer{
		Inventory: client.NodeConfig(),
	}

	server := server4.NewServer(laddr, srv.handler)

	defer server.Close()
	if err := server.ActivateAndServe(); err != nil {
		log.Panic(err)
	}
}
