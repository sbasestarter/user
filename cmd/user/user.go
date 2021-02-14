package main

import (
	"context"
	"time"

	"github.com/jiuzhou-zhao/go-fundamental/dbtoolset"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/jiuzhou-zhao/go-fundamental/servicetoolset"
	"github.com/jiuzhou-zhao/go-fundamental/tracing"
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
	loggerChain := loge.NewLoggerChain()
	loggerChain.AppendLogger(tracing.NewTracingLogger())
	loggerChain.AppendLogger(logger)
	loge.SetGlobalLogger(loge.NewLogger(loggerChain))

	var cfg config.Config
	_, err = libconfig.Load("config", &cfg)
	if err != nil {
		loge.Fatalf(context.Background(), "load config failed: %v", err)
		return
	}
	fixConfig(&cfg)

	dbToolset, err := dbtoolset.NewDBToolset(ctx, &cfg.DBConfig, loggerChain)
	if err != nil {
		loge.Fatalf(context.Background(), "db toolset create failed: %v", err)
		return
	}
	cfg.GRpcServerConfig.DiscoveryExConfig.Setter, err = librediscovery.NewSetter(ctx, loggerChain, dbToolset.GetRedis(),
		"", time.Minute)
	if err != nil {
		loge.Fatalf(context.Background(), "create rediscovery setter failed: %v", err)
		return
	}

	serviceToolset := servicetoolset.NewServerToolset(context.Background(), loggerChain)
	_ = serviceToolset.CreateGRpcServer(&cfg.GRpcServerConfig, nil, func(s *grpc.Server) {
		userpb.RegisterUserServiceServer(s, server.NewUserServer(context.Background(), &cfg))
	})
	serviceToolset.Wait()
}

func fixConfig(cfg *config.Config) {
	if cfg.EmailConfig.SendDelayDuration <= 0 {
		cfg.EmailConfig.SendDelayDuration = time.Second
	}
	if cfg.EmailConfig.ValidDelayDuration <= 0 {
		cfg.EmailConfig.ValidDelayDuration = time.Minute
	}
	if cfg.PhoneConfig.SendDelayDuration <= 0 {
		cfg.PhoneConfig.SendDelayDuration = time.Second
	}
	if cfg.PhoneConfig.ValidDelayDuration <= 0 {
		cfg.PhoneConfig.ValidDelayDuration = time.Minute
	}
	cfg.WhiteListSSOJumpDomainMap = make(map[string]interface{})
	for _, s := range cfg.WhiteListSSOJumpDomain {
		cfg.WhiteListSSOJumpDomainMap[s] = true
	}
	if cfg.GoogleAuthenticator.KeyExpire <= 0 {
		cfg.GoogleAuthenticator.KeyExpire = time.Minute
	}
	if cfg.GoogleAuthenticator.TokenExpire <= 0 {
		cfg.GoogleAuthenticator.TokenExpire = 5 * time.Minute
	}
}
