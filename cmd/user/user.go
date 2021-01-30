package main

import (
	"context"

	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/jiuzhou-zhao/go-fundamental/servicetoolset"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/server"
	"github.com/sgostarter/libconfig"
	"github.com/sgostarter/liblog"
	"google.golang.org/grpc"
)

func main() {
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

	serviceToolset := servicetoolset.NewServerToolset(context.Background(), logger)
	_ = serviceToolset.CreateGRpcServer(&cfg.GRpcServerConfig, nil, func(s *grpc.Server) {
		userpb.RegisterUserServiceServer(s, server.NewUserServer(context.Background(), &cfg))
	})
	serviceToolset.Wait()
}
