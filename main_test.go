package main

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/PolarGeospatialCenter/inventory/pkg/inventory/types"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestDhcpModifiersFromNicConfig(t *testing.T) {

	nicConfig := types.NicConfig{
		IP: []string{
			"192.168.1.1/24",
		},
		Gateway: []string{
			"192.168.1.254",
		},
		DNS: []string{
			"192.168.1.1",
			"192.168.1.2",
		},
	}

	_, ipNet, _ := net.ParseCIDR("192.168.1.1/24")
	// expectedMods := []dhcpv4.Modifier{
	// 	dhcpv4.WithYourIP(net.ParseIP("192.168.1.1")),
	// 	dhcpv4.WithNetmask(ipnet.Mask),
	// 	dhcpv4.WithRouter(net.ParseIP("192.168.1.254")),
	// 	dhcpv4.WithDNS(net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")),
	// }

	_, err := dhcpModifiersFromNicConfig(&nicConfig, ipNet)
	if err != nil {
		t.Errorf("got error from function, %v", err)
	}

	// Check if the set of modifier functions are equal?

}

type MockInventory struct {
}

func (i MockInventory) GetByMac(mac net.HardwareAddr) (*types.InventoryNode, error) {
	mockMac, _ := net.ParseMAC("01:23:45:67:89:ab")

	if mac.String() != mockMac.String() {
		return nil, fmt.Errorf("provided mac %s does not match mock mac %s", mac, mockMac)
	}

	mockNode := &types.InventoryNode{
		Hostname: "test-node-00",
		Networks: map[string]*types.NICInstance{
			"test": &types.NICInstance{
				NIC: types.NICInfo{
					MAC: mockMac,
				},
				Config: types.NicConfig{
					IP: []string{
						"192.168.1.10/24",
					},
					Gateway: []string{
						"192.168.1.1",
					},
					DNS: []string{
						"192.168.1.5",
					},
				},
			},
		},
	}

	return mockNode, nil
}

func TestCreateOfferPacket(t *testing.T) {

	mockIP, mockNet, _ := net.ParseCIDR("192.168.1.10/24")
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mockRequest, _ := dhcpv4.NewDiscovery(mac)
	expectedPacket, _ := dhcpv4.NewReplyFromRequest(mockRequest,
		dhcpv4.WithYourIP(mockIP),
		dhcpv4.WithNetmask(mockNet.Mask),
		dhcpv4.WithDNS(net.ParseIP("192.168.1.5")),
		dhcpv4.WithRouter(net.ParseIP("192.168.1.1")),
		dhcpv4.WithOption(dhcpv4.OptHostName("test-node-00")),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
	)

	mockServer := DHCPServer{
		Inventory: MockInventory{},
		Config: DHCPServerConfig{
			IPNet: mockNet.String(),
		},
	}

	packet, err := mockServer.createOfferPacket(mockRequest)
	if err != nil {
		t.Errorf("got error creating offer packet: %v", err)
	}

	if !reflect.DeepEqual(expectedPacket, packet) {
		t.Errorf("modified offer packet is not equal to expected: \n Expected: %s \n Got: %s", expectedPacket.Summary(), packet.Summary())
	}

}
