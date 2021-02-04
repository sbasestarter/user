package main

import (
	"context"
	"time"

	"github.com/jiuzhou-zhao/go-fundamental/dbtoolset"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/jiuzhou-zhao/go-fundamental/servicetoolset"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/server"
	"github.com/sgostarter/libconfig"
	"github.com/sgostarter/liblog"
	"github.com/sgostarter/librediscovery"
	"google.golang.org/grpc"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, err := liblog.NewZapLogger()
	if err != nil {
		panic(err)
	}
	loge.SetGlobalLogger(loge.NewLogger(logger))

	var cfg config.Config
	_, err = libconfig.Load("config", &cfg)
	if err != nil {
		loge.Fatalf(context.Background(), "load config failed: %v", err)
		return
	}
	fixConfig(&cfg)

	dbToolset, err := dbtoolset.NewDBToolset(ctx, &cfg.DBConfig, logger)
	if err != nil {
		loge.Fatalf(context.Background(), "db toolset create failed: %v", err)
		return
	}
	cfg.GRpcServerConfig.DiscoveryExConfig.Setter, err = librediscovery.NewSetter(ctx, logger, dbToolset.GetRedis(),
		"", time.Minute)
	if err != nil {
		loge.Fatalf(context.Background(), "create rediscovery setter failed: %v", err)
		return
	}

	serviceToolset := servicetoolset.NewServerToolset(context.Background(), logger)
	_ = serviceToolset.CreateGRpcServer(&cfg.GRpcServerConfig, nil, func(s *grpc.Server) {
		userpb.RegisterUserServiceServer(s, server.NewUserServer(context.Background(), &cfg))
	})
	serviceToolset.Wait()
}

func fixConfig(cfg *config.Config) {
	if cfg.EmailConfig.SendDelayDuration == 0 {
		cfg.EmailConfig.SendDelayDuration = time.Second
	}
	if cfg.EmailConfig.ValidDelayDuration == 0 {
		cfg.EmailConfig.ValidDelayDuration = time.Minute
	}
	if cfg.PhoneConfig.SendDelayDuration == 0 {
		cfg.PhoneConfig.SendDelayDuration = time.Second
	}
	if cfg.PhoneConfig.ValidDelayDuration == 0 {
		cfg.PhoneConfig.ValidDelayDuration = time.Minute
	}
}
