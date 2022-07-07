package factory

import (
	"context"

	"github.com/sbasestarter/proto-repo/gen/protorepo-file-center-go"
	"github.com/sbasestarter/proto-repo/gen/protorepo-post-sbs-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/librediscovery/discovery"
	"github.com/sgostarter/libservicetoolset/clienttoolset"
	"google.golang.org/grpc"
)

const (
	gRpcSchema = "grpce"

	serverNamePostKey       = "post"
	serverNameFileCenterKey = "file-center"
)

type GRPCClientFactory interface {
	GetFileCenterClient() filecenterpb.FileCenterClient
	GetPostCenterClient() postsbspb.PostSBSServiceClient
}

type gRPCClientFactoryImpl struct {
	postConn       *grpc.ClientConn
	fileCenterConn *grpc.ClientConn
}

func NewGRPCClientFactory(ctx context.Context, getter discovery.Getter, cfg *config.Config, logger l.Wrapper) GRPCClientFactory {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	err := clienttoolset.RegisterSchemas(ctx, &clienttoolset.RegisterSchemasConfig{
		Getter:  getter,
		Schemas: []string{gRpcSchema},
	}, logger)
	if err != nil {
		logger.Fatalf("register schema failed: %v", err)

		return nil
	}

	postServerName, ok := cfg.DiscoveryServerNames[serverNamePostKey]
	if !ok || postServerName == "" {
		logger.Fatal("no post server name config")

		return nil
	}

	fileCenterServerName, ok := cfg.DiscoveryServerNames[serverNameFileCenterKey]
	if !ok || fileCenterServerName == "" {
		logger.Fatal("no file center server name config")

		return nil
	}

	postConn, err := clienttoolset.DialGRpcServerByName(gRpcSchema, postServerName, &cfg.GRpcClientConfigTpl, nil)
	if err != nil {
		logger.Fatalf("dial %v failed: %v", postServerName, err)

		return nil
	}

	fileCenterConn, err := clienttoolset.DialGRpcServerByName(gRpcSchema, fileCenterServerName, &cfg.GRpcClientConfigTpl, nil)
	if err != nil {
		logger.Fatalf("dial %v failed: %v", fileCenterServerName, err)

		return nil
	}

	return &gRPCClientFactoryImpl{
		postConn:       postConn,
		fileCenterConn: fileCenterConn,
	}
}

func (impl *gRPCClientFactoryImpl) GetFileCenterClient() filecenterpb.FileCenterClient {
	return filecenterpb.NewFileCenterClient(impl.fileCenterConn)
}

func (impl *gRPCClientFactoryImpl) GetPostCenterClient() postsbspb.PostSBSServiceClient {
	return postsbspb.NewPostSBSServiceClient(impl.postConn)
}
