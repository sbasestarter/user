package main

import (
	"context"
	"time"

	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/server"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/liblogrus"
	"github.com/sgostarter/librediscovery"
	"github.com/sgostarter/libservicetoolset/servicetoolset"
	"google.golang.org/grpc"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loggerChain := l.NewLoggerChain()
	loggerChain.AppendLogger(liblogrus.NewLogrus())

	logger := l.NewWrapper(loggerChain)
	logger.GetLogger().SetLevel(l.LevelDebug)

	cfg := config.Get()

	var err error

	cfg.GRpcServerConfig.DiscoveryExConfig.Setter, err = librediscovery.NewSetter(ctx, logger, cfg.RedisCli,
		"", time.Minute)
	if err != nil {
		logger.Fatalf("create rediscovery setter failed: %v", err)
		return
	}

	serviceToolset := servicetoolset.NewServerToolset(context.Background(), logger)

	_ = serviceToolset.CreateGRpcServer(&cfg.GRpcServerConfig, nil, func(s *grpc.Server) error {
		userpb.RegisterUserServiceServer(s, server.NewUserServer(context.Background(), cfg, logger))

		return nil
	})
	serviceToolset.Wait()
}
