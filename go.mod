module github.com/sbasestarter/user

go 1.14

require (
	cloud.google.com/go v0.46.3 // indirect
	github.com/caixw/lib.go v0.0.0-20141220110639-1781da9139e0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-redis/redis/v8 v8.11.5
	github.com/go-sql-driver/mysql v1.6.0
	github.com/go-xorm/xorm v0.7.9
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/issue9/assert v1.3.1
	github.com/issue9/identicon v1.0.1
	github.com/satori/go.uuid v1.2.0
	github.com/sbasestarter/db-orm v0.0.0-20210207070317-7765e0d185ff
	github.com/sbasestarter/proto-repo v0.0.5-0.20210419054605-3a7a0c86d74b
	github.com/sgostarter/i v0.1.11
	github.com/sgostarter/libconfig v0.0.0-20220501124634-dd2bd2401e61
	github.com/sgostarter/libeasygo v0.1.21
	github.com/sgostarter/liblogrus v0.0.9
	github.com/sgostarter/librediscovery v0.0.1
	github.com/sgostarter/libservicetoolset v0.0.18
	github.com/stretchr/testify v1.7.1
	github.com/ttacon/builder v0.0.0-20170518171403-c099f663e1c2 // indirect
	github.com/ttacon/libphonenumber v1.1.0
	golang.org/x/crypto v0.0.0-20220321153916-2c7772ba3064
	google.golang.org/grpc v1.47.0
)

replace github.com/go-xorm/xorm => gitea.com/xorm/xorm v0.7.9
