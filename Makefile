test:
	go test -cover .

linux:
	GOOS=linux go build -o bin/inventory-dhcp-server.linux .

docker: 
	docker build . -t polargeospatialcenter/inventory-dhcp-server:latest