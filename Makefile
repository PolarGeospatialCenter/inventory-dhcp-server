test:
	go test -cover .

linux:
	GOOS=linux go build -o bin/inventory-dhcp-server.linux .