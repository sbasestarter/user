package server

import (
	"context"
	"time"

	"github.com/jiuzhou-zhao/go-fundamental/dbtoolset"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	. "github.com/sbasestarter/user/internal/user/controller"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sgostarter/librediscovery"
)

type UserServer struct {
	controller *Controller
}

func NewUserServer(ctx context.Context, cfg *config.Config) *UserServer {
	dbToolset, err := dbtoolset.NewDBToolset(ctx, &cfg.DBConfig, loge.GetGlobalLogger().GetLogger())
	if err != nil {
		loge.Fatalf(ctx, "init db toolset failed: %v", err)
		return nil
	}
	getter, err := librediscovery.NewGetter(ctx, loge.GetGlobalLogger().GetLogger(), dbToolset.GetRedis(),
		"", 5*time.Minute, time.Minute)
	if err != nil {
		loge.Fatalf(ctx, "new discovery getter failed: %v", err)
		return nil
	}
	return &UserServer{
		controller: NewController(cfg, loge.GetGlobalLogger(), dbToolset.GetRedis(), dbToolset.GetMySQL(),
			factory.NewFactory(ctx, getter, cfg)),
	}
}

func (us *UserServer) makeStatus(status userpb.UserStatus, err error) *userpb.ServerStatus {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return us.makeStatusWithMsg(status, msg)
}

func (us *UserServer) makeStatusWithMsg(status userpb.UserStatus, msg string) *userpb.ServerStatus {
	if msg == "" {
		msg = status.String()
	}
	return &userpb.ServerStatus{
		Status: status,
		Msg:    msg,
	}
}

func (us *UserServer) makeSignResponseNoSSOToken(status userpb.UserStatus, token string, info *userpb.UserInfo,
	err error) *userpb.SignResponse {
	return us.makeSignResponse(status, token, info, "", err)
}

func (us *UserServer) makeSignResponse(status userpb.UserStatus, token string, info *userpb.UserInfo, ssoToken string,
	err error) *userpb.SignResponse {
	return &userpb.SignResponse{
		Status:   us.makeStatus(status, err),
		Token:    token,
		Info:     info,
		SsoToken: ssoToken,
	}
}

func (us *UserServer) TriggerAuth(ctx context.Context, req *userpb.TriggerAuthRequest) (*userpb.TriggerAuthResponse, error) {
	return &userpb.TriggerAuthResponse{
		Status: us.makeStatus(us.controller.TriggerAuth(ctx, req.User)),
	}, nil
}

func (us *UserServer) Register(ctx context.Context, req *userpb.RegisterRequest) (*userpb.SignResponse, error) {
	return us.makeSignResponse(us.controller.Register(ctx, req.User, req.CodeForVe, req.NewPassword,
		req.AttachSsoToken)), nil
}

func (us *UserServer) Login(ctx context.Context, req *userpb.LoginRequest) (*userpb.SignResponse, error) {
	return us.makeSignResponse(us.controller.Login(ctx, req.User, req.Password, req.CodeForVe, req.CodeForGa,
		req.AttachSsoToken)), nil
}

func (us *UserServer) SSOLogin(ctx context.Context, req *userpb.SSOLoginRequest) (*userpb.SignResponse, error) {
	return us.makeSignResponseNoSSOToken(us.controller.SSOLogin(ctx, req.SsoToken)), nil
}

func (us *UserServer) Logout(ctx context.Context, req *userpb.LogoutRequest) (*userpb.LogoutResponse, error) {
	return &userpb.LogoutResponse{
		Status: us.makeStatus(us.controller.Logout(ctx, req.Token)),
	}, nil
}

func (us *UserServer) GoogleAuthGetSetupInfo(ctx context.Context, req *userpb.GoogleAuthGetSetupInfoRequest) (
	*userpb.GoogleAuthGetSetupInfoResponse, error) {
	status, key, err := us.controller.GoogleAuthGetSetupInfo(ctx, req.Token)
	return &userpb.GoogleAuthGetSetupInfoResponse{
		Status:    us.makeStatus(status, err),
		SecretKey: key,
	}, nil
}

func (us *UserServer) GoogleAuthVerify(ctx context.Context, req *userpb.GoogleAuthVerifyRequest) (
	*userpb.GoogleAuthVerifyResponse, error) {
	status, token, err := us.controller.GoogleAuthVerify(ctx, req.Token, req.Code)
	return &userpb.GoogleAuthVerifyResponse{
		Status: us.makeStatus(status, err),
		Token:  token,
	}, nil
}

func (us *UserServer) GoogleAuthSet(ctx context.Context, req *userpb.GoogleAuthSetRequest) (*userpb.GoogleAuthSetResponse, error) {
	return &userpb.GoogleAuthSetResponse{
		Status: us.makeStatus(us.controller.GoogleAuthSet(ctx, req.Token, req.Code, req.TokenGaOld)),
	}, nil
}

func (us *UserServer) Profile(ctx context.Context, req *userpb.ProfileRequest) (*userpb.ProfileResponse, error) {
	status, userInfo, ssoToken, err := us.controller.Profile(ctx, req.Token, req.AttachSsoToken)
	return &userpb.ProfileResponse{
		Status:   us.makeStatus(status, err),
		Info:     userInfo,
		SsoToken: ssoToken,
	}, nil
}

func (us *UserServer) ResetPassword(ctx context.Context, req *userpb.ResetPasswordRequest) (*userpb.SignResponse, error) {
	return us.makeSignResponseNoSSOToken(us.controller.ResetPassword(ctx, req.User, req.NewPassword,
		req.CodeForVe, req.CodeForGa)), nil
}

func (us *UserServer) ChangePassword(ctx context.Context, req *userpb.ChangePasswordRequest) (*userpb.SignResponse, error) {
	return us.makeSignResponseNoSSOToken(us.controller.ChangePassword(ctx, req.Token, req.CsrfToken, req.Password,
		req.NewPassword)), nil
}

func (us *UserServer) GetCsrfToken(ctx context.Context, req *userpb.GetCsrfTokenRequest) (
	*userpb.GetCsrfTokenResponse, error) {
	status, csrfToken, err := us.controller.GetCsrfToken(ctx, req.Token)
	return &userpb.GetCsrfTokenResponse{
		Status:    us.makeStatus(status, err),
		CsrfToken: csrfToken,
	}, nil
}

func (us *UserServer) GetDetailInfo(ctx context.Context, req *userpb.GetDetailInfoRequest) (*userpb.GetDetailInfoResponse, error) {
	status, userInfo, err := us.controller.GetDetailInfo(ctx, req.Token)
	return &userpb.GetDetailInfoResponse{
		Status: us.makeStatus(status, err),
		Info:   userInfo,
	}, nil
}

func (us *UserServer) UpdateDetailInfo(ctx context.Context, req *userpb.UpdateDetailInfoRequest) (*userpb.UpdateDetailInfoResponse, error) {
	return &userpb.UpdateDetailInfoResponse{
		Status: us.makeStatus(us.controller.UpdateDetailInfo(ctx, req.Token, req.CsrfToken, req.Avatar, req.NickName, req.Phone, req.Email, req.WeChat)),
	}, nil
}

func (us *UserServer) AdminProfile(ctx context.Context, req *userpb.AdminProfileRequest) (*userpb.AdminProfileResponse, error) {
	status, userInfo, err := us.controller.AdminProfile(ctx, req.Token)
	return &userpb.AdminProfileResponse{
		Status: us.makeStatus(status, err),
		Info:   userInfo,
	}, nil
}
