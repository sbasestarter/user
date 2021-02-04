package controller

import (
	"context"
	postsbspb "github.com/sbasestarter/proto-repo/gen/protorepo-post-sbs-go"
	"os"
	"testing"

	"github.com/jiuzhou-zhao/go-fundamental/dbtoolset"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/jiuzhou-zhao/go-fundamental/utils"
	"github.com/sbasestarter/db-orm/go/user"
	"github.com/sbasestarter/proto-repo/gen/protorepo-file-center-go"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sbasestarter/user/internal/user/helper"
	"github.com/sgostarter/libconfig"
	"google.golang.org/grpc"
)

var TestToolset *dbtoolset.DBToolset
var TestController *Controller
var TestCfg *config.Config
var TestPeerIp = "127.0.0.1"
var TestUserId = &userpb.UserId{
	UserName: "abcd@qq.com",
	UserVe:   userpb.VerificationEquipment_VEMail.String(),
}

func TCasePre() {
	TestPeerIp = "127.0.0.1"

	_, _ = TestToolset.GetMySQL().Where("true").Delete(&user.UserAuthentication{})
	_, _ = TestToolset.GetMySQL().Where("true").Delete(&user.UserSource{})
	_, _ = TestToolset.GetMySQL().Where("true").Delete(&user.UserInfo{})
	_, _ = TestToolset.GetMySQL().Where("true").Delete(&user.UserExt{})
	_, _ = TestToolset.GetMySQL().Where("true").Delete(&user.UserTrust{})

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthCode))
	})

	TestCfg.GoogleAuthenticator.Force = false
}

type fakeFileCenterClient struct {
}

func (c *fakeFileCenterClient) UpdateFile(ctx context.Context, in *filecenterpb.UpdateFileRequest,
	opts ...grpc.CallOption) (*filecenterpb.UpdateFileResponse, error) {
	return &filecenterpb.UpdateFileResponse{
		Status: &filecenterpb.ServerStatus{
			Status: filecenterpb.FileCenterStatus_FCS_SUCCESS,
		},
	}, nil
}

type fakePostCenterClient struct {
}

func (c *fakePostCenterClient) PostCode(ctx context.Context, in *postsbspb.PostCodeRequest,
	opts ...grpc.CallOption) (*postsbspb.PostCodeResponse, error) {
	return &postsbspb.PostCodeResponse{
		Status: &postsbspb.ServerStatus{
			Status: postsbspb.PostSBSStatus_PS_SBS_SUCCESS,
		},
	}, nil
}

type fakeGRPCClientFactory struct {
}

func (f *fakeGRPCClientFactory) GetFileCenterClient() filecenterpb.FileCenterClient {
	return &fakeFileCenterClient{}
}

func (f *fakeGRPCClientFactory) GetPostCenterClient() postsbspb.PostSBSServiceClient {
	return &fakePostCenterClient{}
}

type fakeUtils struct {
	utils factory.Utils
}

func (u *fakeUtils) RandomString(n int, allowedChars ...[]rune) string {
	return u.utils.RandomString(n, allowedChars...)
}

func (u *fakeUtils) GetPeerIp(ctx context.Context) string {
	return TestPeerIp
}

type fakeHttpToken struct{}

func (t *fakeHttpToken) SetUserTokenCookie(ctx context.Context, token string) error {
	return nil
}
func (t *fakeHttpToken) UnsetUserTokenCookie(ctx context.Context, token string) error {
	return nil
}

type fakeFactory struct{}

func (impl *fakeFactory) GetGRPCClientFactory() factory.GRPCClientFactory {
	return &fakeGRPCClientFactory{}
}

func (impl *fakeFactory) GetUtils() factory.Utils {
	return &fakeUtils{utils: helper.NewUtilsImpl()}
}

func (impl *fakeFactory) GetHttpToken() factory.HttpToken {
	return &fakeHttpToken{}
}

func TestMain(m *testing.M) {
	logger := loge.NewLogger(nil)

	var cfg config.Config
	_, _ = libconfig.Load("config", &cfg)
	TestCfg = &cfg

	TestToolset, _ = dbtoolset.NewDBToolset(context.Background(), &cfg.DBConfig, logger.GetLogger())

	cfg.DummyVerifyCode = "12312"
	cfg.GoogleAuthenticator.Enable = true

	TestController = NewController(&cfg, logger, TestToolset.GetRedis(), TestToolset.GetMySQL(), &fakeFactory{})

	os.Exit(m.Run())
}
