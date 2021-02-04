package factory

import (
	"context"

	"github.com/jiuzhou-zhao/go-fundamental/clienttoolset"
	"github.com/jiuzhou-zhao/go-fundamental/discovery"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/sbasestarter/proto-repo/gen/protorepo-file-center-go"
	"github.com/sbasestarter/proto-repo/gen/protorepo-post-sbs-go"
	"github.com/sbasestarter/user/internal/config"
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

func NewGRPCClientFactory(ctx context.Context, getter discovery.Getter, cfg *config.Config) GRPCClientFactory {
	err := clienttoolset.RegisterSchemas(ctx, &clienttoolset.RegisterSchemasConfig{
		Getter:  getter,
		Logger:  loge.GetGlobalLogger().GetLogger(),
		Schemas: []string{gRpcSchema},
	})
	if err != nil {
		loge.Fatalf(ctx, "register schema failed: %v", err)
		return nil
	}
	postServerName, ok := cfg.DiscoveryServerNames[serverNamePostKey]
	if !ok || postServerName == "" {
		loge.Fatal(ctx, "no post server name config")
		return nil
	}

	fileCenterServerName, ok := cfg.DiscoveryServerNames[serverNameFileCenterKey]
	if !ok || fileCenterServerName == "" {
		loge.Fatal(ctx, "no file center server name config")
		return nil
	}

	postConn, err := clienttoolset.DialGRpcServerByName(gRpcSchema, postServerName, nil)
	if err != nil {
		loge.Fatalf(ctx, "dial %v failed: %v", postServerName, err)
		return nil
	}
	fileCenterConn, err := clienttoolset.DialGRpcServerByName(gRpcSchema, fileCenterServerName, nil)
	if err != nil {
		loge.Fatalf(ctx, "dial %v failed: %v", fileCenterServerName, err)
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
