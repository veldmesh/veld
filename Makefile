.PHONY: build build-all tray proto test lint docker clean

build:
	go build -o bin/veld-daemon ./cmd/veld-daemon
	go build -o bin/veld-coord ./cmd/veld-coord
	go build -o bin/veld ./cmd/veld

# tray requires CGO and platform libraries — built separately from the pure-Go targets.
tray:
	cd tray && go build -o ../bin/veld-tray .

build-all: build-win build-darwin build-linux build-mips

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/linux_amd64/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/linux_amd64/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/linux_amd64/veld ./cmd/veld
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/linux_arm64/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/linux_arm64/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/linux_arm64/veld ./cmd/veld
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o dist/linux_arm_v7/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o dist/linux_arm_v7/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o dist/linux_arm_v7/veld ./cmd/veld
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o dist/linux_arm_v6/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o dist/linux_arm_v6/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o dist/linux_arm_v6/veld ./cmd/veld
build-mips:
	CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -o dist/linux_mips/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -o dist/linux_mips/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -o dist/linux_mips/veld ./cmd/veld
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -o dist/linux_mipsle/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -o dist/linux_mipsle/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -o dist/linux_mipsle/veld ./cmd/veld

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/darwin_amd64/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/darwin_amd64/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/darwin_amd64/veld ./cmd/veld
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/darwin_arm64/veld-daemon ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/darwin_arm64/veld-coord ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/darwin_arm64/veld ./cmd/veld

build-win:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows_amd64/veld-daemon.exe ./cmd/veld-daemon
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows_amd64/veld-coord.exe ./cmd/veld-coord
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows_amd64/veld.exe ./cmd/veld


proto:
	protoc --go_out=gen --go_opt=paths=source_relative \
		--go-grpc_out=gen --go-grpc_opt=paths=source_relative \
		-I proto \
		proto/veld/coord/v1/coord.proto

test:
	go test ./...

lint:
	golangci-lint run ./...

docker:
	docker build -t veld-coord:latest -f Dockerfile .

clean:
	rm -rf bin/ dist/
	cd tray && go clean
