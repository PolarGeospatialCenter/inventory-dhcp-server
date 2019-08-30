package main

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/PolarGeospatialCenter/inventory-client/pkg/api/client"
	"github.com/PolarGeospatialCenter/inventory/pkg/inventory/types"
	beeline "github.com/honeycombio/beeline-go"
	"github.com/honeycombio/beeline-go/trace"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestDhcpModifiersFromIPReservation(t *testing.T) {

	mockServer := DHCPServer{
		Inventory: MockInventory{},
		Networks: MockNetworkInventory{},
		Config: DHCPServerConfig{
			IPNet:            "192.168.1.0/24",
			NextServer:       "192.168.1.50",
			Filename:         "test.img",
			ServerIdentifier: "192.168.1.254",
		},
	}

	reservation := &types.IPReservation{
		IP:      &net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
		Gateway: net.ParseIP("192.168.1.254"),
		DNS: []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
		},
		Metadata: map[string]interface{}{
			"dhcp_options": map[string]interface{}{
				"filename": "http://nexthost.local/ipxe?mac=${mac}",
			},
		},
	}

	_, err := mockServer.modifiersFromIPReservation(reservation)
	if err != nil {
		t.Errorf("got error from function, %v", err)
	}
}

func TestBootFilenameFromIPReservation(t *testing.T) {

	mockServer := DHCPServer{
		Config: DHCPServerConfig{
			Filename:         "test.img",
		},
	}

	reservation := &types.IPReservation{
		Metadata: map[string]interface{}{
			"dhcp_options": map[string]interface{}{
				"filename": "http://nexthost.local/ipxe?mac=${mac}",
			},
		},
	}

	filename := mockServer.getBootFilenameFromIPReservation(reservation)
	if filename != "http://nexthost.local/ipxe?mac=${mac}" {
		t.Errorf("Expected iPXE url, got %s", filename)
	}

	filename = mockServer.getBootFilenameFromIPReservation(&types.IPReservation{}) 
	if filename != "test.img" {
		t.Errorf("Expected default filename, got %s", filename)
	}
}



type MockNetworkInventory struct{}

func (i MockNetworkInventory) GetAll() ([]*types.Network, error) {
	return []*types.Network{}, nil
}

type MockInventory struct {
	reservations []*types.IPReservation
}

func (i MockInventory) CreateIPReservation(req *types.IpamIpRequest, ip net.IP) (*types.IPReservation, error) {
	mac, _ := net.ParseMAC(req.HwAddress)
	if r, err := i.GetIPReservationsByMAC(mac); len(r) == 0 && err == nil {
		res := &types.IPReservation{
			IP:              &net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
			MAC:             mac,
			HostInformation: "test-node-00",
			Gateway:         net.ParseIP("192.168.1.1"),
			DNS: []net.IP{
				net.ParseIP("192.168.1.5"),
			},
		}
		i.reservations = append(i.reservations, res)
		return res, nil
	}
	return nil, client.ErrConflict
}

func (i MockInventory) GetIPReservation(ip net.IP) (*types.IPReservation, error) {
	for _, res := range i.reservations {
		if res.IP.IP.Equal(ip) {
			return res, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (i MockInventory) GetIPReservationsByMAC(mac net.HardwareAddr) (types.IPReservationList, error) {
	for _, res := range i.reservations {
		if res.MAC.String() == mac.String() {
			return types.IPReservationList{res}, nil
		}
	}
	return types.IPReservationList{}, nil
}

func (i MockInventory) UpdateIPReservation(modified *types.IPReservation) (*types.IPReservation, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestCreateOfferPacket(t *testing.T) {

	mockIP, mockNet, _ := net.ParseCIDR("192.168.1.10/24")
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mockRequest, _ := dhcpv4.NewDiscovery(mac)
	mockRequest.GatewayIPAddr = net.ParseIP("192.168.1.1")

	expectedPacket, _ := dhcpv4.NewReplyFromRequest(mockRequest,
		dhcpv4.WithYourIP(mockIP),
		dhcpv4.WithNetmask(mockNet.Mask),
		dhcpv4.WithDNS(net.ParseIP("192.168.1.5")),
		dhcpv4.WithRouter(net.ParseIP("192.168.1.1")),
		dhcpv4.WithOption(dhcpv4.OptHostName("test-node-00")),
		dhcpv4.WithOption(dhcpv4.OptTFTPServerName("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptBootFileName("test.img")),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithServerIP(net.ParseIP("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.254"))),
		dhcpv4.WithLeaseTime(12*3600),
	)

	mockServer := DHCPServer{
		Inventory: MockInventory{
			reservations: []*types.IPReservation{
				&types.IPReservation{
					IP:       &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					MAC:      mac,
					Metadata: types.Metadata{"hostname": "test-node-00"},
					Gateway:  net.ParseIP("192.168.1.1"),
					DNS: []net.IP{
						net.ParseIP("192.168.1.5"),
					},
				},
			},
		},
		Networks: MockNetworkInventory{},
		Config: DHCPServerConfig{
			IPNet:            mockNet.String(),
			NextServer:       "192.168.1.50",
			Filename:         "test.img",
			ServerIdentifier: "192.168.1.254",
		},
	}

	beeline.Init(beeline.Config{STDOUT: true})
	ctx, _ := trace.NewTrace(context.Background(), "")
	packet, err := mockServer.createOfferPacket(ctx, mockRequest)
	if err != nil {
		t.Errorf("got error creating offer packet: %v", err)
	}

	if !reflect.DeepEqual(expectedPacket, packet) {
		t.Errorf("modified offer packet is not equal to expected: \n Expected: %s \n Got: %s", expectedPacket.Summary(), packet.Summary())
	}
}

func TestGetSubnetIPWithOption82(t *testing.T) {

	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mockRequest, _ := dhcpv4.NewDiscovery(mac)
	dhcpv4.WithGeneric(dhcpv4.OptionRelayAgentInformation, []byte{
		1, 5, 'l', 'i', 'n', 'u', 'x',
		2, 4, 'b', 'o', 'o', 't',
		5, 4, 192, 168, 1, 1,
	})(mockRequest)

	subnetIP := getSubnetIPFromRequest(mockRequest)
	if subnetIP.String() != "192.168.1.1" {
		t.Errorf("Wrong subnet returned: %s", subnetIP)
	}
}

func TestCreateOfferPacketWithOption82(t *testing.T) {

	mockIP, mockNet, _ := net.ParseCIDR("192.168.1.10/24")
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mockRequest, _ := dhcpv4.NewDiscovery(mac)
	dhcpv4.WithGeneric(dhcpv4.OptionRelayAgentInformation, []byte{
		1, 5, 'l', 'i', 'n', 'u', 'x',
		2, 4, 'b', 'o', 'o', 't',
		5, 4, 192, 168, 1, 1,
	})(mockRequest)

	expectedPacket, _ := dhcpv4.NewReplyFromRequest(mockRequest,
		dhcpv4.WithYourIP(mockIP),
		dhcpv4.WithNetmask(mockNet.Mask),
		dhcpv4.WithDNS(net.ParseIP("192.168.1.5")),
		dhcpv4.WithRouter(net.ParseIP("192.168.1.1")),
		dhcpv4.WithOption(dhcpv4.OptHostName("test-node-00")),
		dhcpv4.WithOption(dhcpv4.OptTFTPServerName("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptBootFileName("test.img")),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithServerIP(net.ParseIP("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.254"))),
		dhcpv4.WithLeaseTime(12*3600),
		dhcpv4.WithGeneric(dhcpv4.OptionRelayAgentInformation, []byte{
			1, 5, 'l', 'i', 'n', 'u', 'x',
			2, 4, 'b', 'o', 'o', 't',
			5, 4, 192, 168, 1, 1,
		}),
	)

	mockServer := DHCPServer{
		Inventory: MockInventory{
			reservations: []*types.IPReservation{
				&types.IPReservation{
					IP:       &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					MAC:      mac,
					Metadata: types.Metadata{"hostname": "test-node-00"},
					Gateway:  net.ParseIP("192.168.1.1"),
					DNS: []net.IP{
						net.ParseIP("192.168.1.5"),
					},
				},
			},
		},
		Networks: MockNetworkInventory{},
		Config: DHCPServerConfig{
			IPNet:            mockNet.String(),
			NextServer:       "192.168.1.50",
			Filename:         "test.img",
			ServerIdentifier: "192.168.1.254",
		},
	}

	beeline.Init(beeline.Config{STDOUT: true})
	ctx, _ := trace.NewTrace(context.Background(), "")
	packet, err := mockServer.createOfferPacket(ctx, mockRequest)
	if err != nil {
		t.Errorf("got error creating offer packet: %v", err)
	}

	if !reflect.DeepEqual(expectedPacket, packet) {
		t.Errorf("modified offer packet is not equal to expected: \n Expected: %s \n Got: %s", expectedPacket.Summary(), packet.Summary())
	}

}

func TestCreateAckPacket(t *testing.T) {

	mockIP, mockNet, _ := net.ParseCIDR("192.168.1.10/24")
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")

	mockRequest, _ := dhcpv4.NewReplyFromRequest(&dhcpv4.DHCPv4{},
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(mockIP)),
		dhcpv4.WithRelay(net.ParseIP("192.168.1.1")))

	expectedPacket, _ := dhcpv4.NewReplyFromRequest(mockRequest,
		dhcpv4.WithYourIP(mockIP),
		dhcpv4.WithNetmask(mockNet.Mask),
		dhcpv4.WithDNS(net.ParseIP("192.168.1.5")),
		dhcpv4.WithRouter(net.ParseIP("192.168.1.1")),
		dhcpv4.WithOption(dhcpv4.OptHostName("test-node-00")),
		dhcpv4.WithOption(dhcpv4.OptTFTPServerName("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptBootFileName("test.img")),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithServerIP(net.ParseIP("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.254"))),
		dhcpv4.WithLeaseTime(12*3600),
	)

	mockServer := DHCPServer{
		Inventory: MockInventory{
			reservations: []*types.IPReservation{
				&types.IPReservation{
					IP:       &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					MAC:      mac,
					Metadata: types.Metadata{"hostname": "test-node-00"},
					Gateway:  net.ParseIP("192.168.1.1"),
					DNS: []net.IP{
						net.ParseIP("192.168.1.5"),
					},
				},
			},
		},
		Networks: MockNetworkInventory{},
		Config: DHCPServerConfig{
			IPNet:            mockNet.String(),
			NextServer:       "192.168.1.50",
			Filename:         "test.img",
			ServerIdentifier: "192.168.1.254",
		},
	}

	beeline.Init(beeline.Config{STDOUT: true})
	ctx, _ := trace.NewTrace(context.Background(), "")
	packet, err := mockServer.createAckNakPacket(ctx, mockRequest)
	if err != nil {
		t.Errorf("got error creating ack packet: %v", err)
	}

	if !reflect.DeepEqual(expectedPacket, packet) {
		t.Errorf("modified ack packet is not equal to expected: \n Expected: %s \n Got: %s", expectedPacket.Summary(), packet.Summary())
	}

}

func TestValidPacket(t *testing.T) {

	mockIP, mockNet, _ := net.ParseCIDR("192.168.1.10/24")
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mockRequest, _ := dhcpv4.NewDiscovery(mac)
	mockPacket, _ := dhcpv4.NewReplyFromRequest(mockRequest,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(mockIP)),
		dhcpv4.WithNetmask(mockNet.Mask),
		dhcpv4.WithDNS(net.ParseIP("192.168.1.5")),
		dhcpv4.WithRouter(net.ParseIP("192.168.1.1")),
		dhcpv4.WithOption(dhcpv4.OptHostName("test-node-00")),
		dhcpv4.WithOption(dhcpv4.OptTFTPServerName("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptBootFileName("test.img")),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithRelay(net.ParseIP("192.168.1.1")),
	)

	mockServer := DHCPServer{
		Inventory: MockInventory{
			reservations: []*types.IPReservation{
				&types.IPReservation{
					IP:              &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0)},
					MAC:             mac,
					HostInformation: "test-node-00",
					Gateway:         net.ParseIP("192.168.1.1"),
					DNS: []net.IP{
						net.ParseIP("192.168.1.5"),
					},
				},
			},
		},
		Networks: MockNetworkInventory{},
		Config: DHCPServerConfig{
			IPNet:      mockNet.String(),
			NextServer: "192.168.1.50",
			Filename:   "test.img",
		},
	}

	beeline.Init(beeline.Config{STDOUT: true})
	ctx, _ := trace.NewTrace(context.Background(), "")

	expectedPacket, err := mockServer.createOfferPacket(ctx, mockPacket)
	if err != nil {
		t.Errorf("unable to generate expected packet: %v", err)
	}

	t.Log(expectedPacket, mockPacket)
	valid, err := mockServer.validPacket(expectedPacket, mockPacket)
	if err != nil {
		t.Errorf("got error creating offer packet: %v", err)
	}

	if !valid {
		t.Errorf("packet is valid but validPacket returned false")
	}
}

func TestValidPacketInvalid(t *testing.T) {

	mockIP, mockNet, _ := net.ParseCIDR("192.168.1.11/24")
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mockRequest, _ := dhcpv4.NewDiscovery(mac)
	mockPacket, _ := dhcpv4.NewReplyFromRequest(mockRequest,
		dhcpv4.WithYourIP(mockIP),
		dhcpv4.WithNetmask(mockNet.Mask),
		dhcpv4.WithDNS(net.ParseIP("192.168.1.5")),
		dhcpv4.WithRouter(net.ParseIP("192.168.1.1")),
		dhcpv4.WithOption(dhcpv4.OptHostName("test-node-00")),
		dhcpv4.WithOption(dhcpv4.OptTFTPServerName("192.168.1.50")),
		dhcpv4.WithOption(dhcpv4.OptBootFileName("test.img")),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
	)

	mockServer := DHCPServer{
		Inventory: MockInventory{},
		Networks:  MockNetworkInventory{},
		Config: DHCPServerConfig{
			IPNet:      mockNet.String(),
			NextServer: "192.168.1.50",
			Filename:   "test.img",
		},
	}

	beeline.Init(beeline.Config{STDOUT: true})
	ctx, _ := trace.NewTrace(context.Background(), "")
	expectedPacket, _ := mockServer.createOfferPacket(ctx, mockPacket)

	valid, err := mockServer.validPacket(expectedPacket, mockPacket)
	if err != nil {
		t.Errorf("got error creating offer packet: %v", err)
	}

	if valid {
		t.Errorf("packet is not valid but validPacket returned true")
	}
}
