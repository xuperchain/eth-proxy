module github.com/xuperchain/xuperproxy

go 1.13

require (
	github.com/golang/protobuf v1.5.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/rpc v1.2.0
	github.com/hyperledger/burrow v0.30.5
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1
	github.com/xuperchain/xuper-sdk-go/v2 v2.0.0-20210722084115-86d72d395950
	github.com/xuperchain/xuperchain v0.0.0-20210720132849-0079bcda5e54
	github.com/xuperchain/xupercore v0.0.0-20210720112551-29ed46a49f02
	go.uber.org/zap v1.16.0
	google.golang.org/grpc v1.36.0
)

replace github.com/hyperledger/burrow => github.com/xuperchain/burrow v0.30.6-0.20210806065218-1c6d40be4365
