package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sbasestarter/db-orm/go/user"
	filecenterpb "github.com/sbasestarter/proto-repo/gen/protorepo-file-center-go"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sbasestarter/user/internal/user/controller/plugins"
	"github.com/sbasestarter/user/internal/user/model"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/libeasygo/helper"
	"xorm.io/xorm"
)

type Controller struct {
	cfg             *config.Config
	logger          l.WrapperWithContext
	redis           *redis.Client
	m               *model.Model
	fileCli         filecenterpb.FileCenterClient
	authPlugins     *plugins.Plugins
	cliFactory      factory.GRPCClientFactory
	utils           factory.Utils
	httpToken       factory.HTTPToken
	whiteListTokens map[string]*AuthInfo
}

func NewController(cfg *config.Config, logger l.Wrapper, redis *redis.Client, db *xorm.Engine, allFactory factory.Factory) *Controller {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	loggerWithContext := logger.GetWrapperWithContext()

	uUtils := allFactory.GetUtils()
	cliFactory := allFactory.GetGRPCClientFactory()
	whiteListTokens := make(map[string]*AuthInfo)

	for _, token := range cfg.WhiteListTokens {
		decodeBytes, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			loggerWithContext.Fatalf(context.Background(), "parse white list token failed:", err, token)
		}

		var ai AuthInfo

		err = json.Unmarshal(decodeBytes, &ai)
		if err != nil {
			loggerWithContext.Fatalf(context.Background(), "parse white list token failed:", err, token)
		}

		whiteListTokens[token] = &ai
	}

	return &Controller{
		cfg:             cfg,
		logger:          loggerWithContext.WithFields(l.StringField(l.ClsKey, "Controller")),
		redis:           redis,
		m:               model.NewModel(db, uUtils),
		fileCli:         cliFactory.GetFileCenterClient(),
		authPlugins:     plugins.NewPlugins(cfg, cliFactory, logger),
		cliFactory:      cliFactory,
		utils:           uUtils,
		httpToken:       allFactory.GetHTTPToken(),
		whiteListTokens: whiteListTokens,
	}
}

func (c *Controller) TriggerAuth(ctx context.Context, user *userpb.UserId, purpose userpb.TriggerAuthPurpose) (userpb.UserStatus, error) {
	if user == nil || user.UserVe == "" {
		return userpb.UserStatus_US_FAILED, errors.New("invalid input")
	}

	status, fixedUser, err := c.authPlugins.FixUserID(ctx, user)
	if status != userpb.UserStatus_US_SUCCESS {
		return status, err
	}

	user = fixedUser

	// check freq
	key := redisKeyForVeAuth(redisUsername(user), keyCatAuthLock)

	// nolint: contextcheck
	helper.DoWithTimeout(context.Background(), time.Second, func(ctx context.Context) {
		_, err = c.redis.Get(ctx, key).Result()
	})

	if !errors.Is(err, redis.Nil) {
		if err != nil {
			c.logger.Errorf(ctx, "redis error: %v", err)

			return userpb.UserStatus_US_INTERNAL_ERROR, err
		}

		return userpb.UserStatus_US_VERIFY_TOO_QUICK, err
	}

	// nolint: contextcheck
	helper.DoWithTimeout(context.Background(), time.Second, func(ctx context.Context) {
		_, err = c.redis.SetNX(ctx, key, time.Now().Format("20060102.150405.000"),
			c.authPlugins.SendLockTimeDuration(ctx, user)).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "check verify limit failed: %v", err)

		return userpb.UserStatus_US_INTERNAL_ERROR, err
	}

	status, code, err := c.authPlugins.TriggerAuthentication(ctx, user, purpose)
	if status != userpb.UserStatus_US_SUCCESS {
		return status, err
	}

	// save verify code
	key = redisKeyForVeAuth(redisUsername(user), keyCatAuthCode)

	// nolint: contextcheck
	helper.DoWithTimeout(context.Background(), time.Second, func(ctx context.Context) {
		_, err = c.redis.Set(ctx, key, code, c.authPlugins.ValidDelayDuration(ctx, user)).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "save verify code error: %v", err)

		return userpb.UserStatus_US_INTERNAL_ERROR, nil
	}

	return userpb.UserStatus_US_SUCCESS, nil
}

func (c *Controller) Register(ctx context.Context, user *userpb.UserId, codeForVe, newPassword string,
	attachSsoToken bool, ssoJumpURL string) (status userpb.UserStatus, token string, info *userpb.UserInfo, ssoToken string, err error) {
	if user == nil || user.UserVe == "" || newPassword == "" {
		c.logger.Errorf(ctx, "invalid input: %+v, %v", user, newPassword)

		status = userpb.UserStatus_US_FAILED

		return
	}

	if codeForVe == "" {
		status = userpb.UserStatus_US_NEED_VE_AUTH

		return
	}

	status, fixedUser, err := c.authPlugins.FixUserID(ctx, user)
	if status != userpb.UserStatus_US_SUCCESS {
		return
	}

	user = fixedUser

	status, err = c.checkVe(user, codeForVe)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "checkVe failed: %v", err)

		return
	}

	avatar, err := c.newAvatar(ctx, user.UserName)
	if err != nil {
		c.logger.Warnf(ctx, "new avatar failed: %v", err)

		avatar = ""
	}

	status, nickName := c.authPlugins.GetNickName(ctx, user)
	if status == userpb.UserStatus_US_DONT_SUPPORT {
		nickName = user.UserName
	} else if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Warnf(ctx, "get nickName failed: %v", err)

		nickName = user.UserName
	}

	password, err := c.passEncrypt(newPassword)
	if err != nil {
		c.logger.Errorf(ctx, "pass encrypt failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status, userInfo, err := c.m.NewUser(user.UserName, user.UserVe, password, nickName, avatar)
	if err != nil {
		c.logger.Errorf(ctx, "new user failed: %v-%v", status, err)

		return
	}

	status, ssoToken, token, info, err = c.signResponseInfoAfterCheckPassEx(ctx, userInfo.UserId, userInfo,
		model.UserTrustRegisterNumber, attachSsoToken, ssoJumpURL)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "signResponseInfoAfterCheckPass failed: %v, %v", status, err)

		return
	}

	c.removeVe(user)

	if c.cfg.GoogleAuthenticator.Force {
		status = userpb.UserStatus_US_NEED_2FA_SETUP
	} else {
		status = userpb.UserStatus_US_SUCCESS
	}

	return
}

// nolint: funlen, gocognit, cyclop
func (c *Controller) Login(ctx context.Context, userID *userpb.UserId, password, codeForVe, codeForGa string,
	attachSsoToken bool, ssoJumpURL string) (status userpb.UserStatus, token string, info *userpb.UserInfo, ssoToken string, err error) {
	if userID == nil || userID.UserVe == "" {
		c.logger.Errorf(ctx, "invalid input: %+v", userID)

		status = userpb.UserStatus_US_FAILED

		return
	}

	var authInfo *AuthInfo

	var nickName string

	status, fixedUser, nickName, avatar := c.authPlugins.TryAutoLogin(ctx, userID, codeForVe)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Warnf(ctx, "auto login failed: %v", status)
	} else {
		c.logger.Info(ctx, "auto login success")

		userID = fixedUser

		var userSource *user.UserSource

		userSource, err = c.m.MustUserSource(userID.UserName, userID.UserVe)
		if err != nil {
			c.logger.Errorf(ctx, "must userID source failed: %v", err)
			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}

		userID := userSource.Id
		userSourceIDFlag := true

		if userSource.UserId > 0 {
			userID = userSource.UserId
			userSourceIDFlag = false
		}

		authInfo = &AuthInfo{
			UserSourceIDFlag: userSourceIDFlag,
			UserID:           userID,
			NickName:         nickName,
			Avatar:           avatar,
		}
	}

	// nolint: nestif
	if authInfo == nil {
		var fixedUser *userpb.UserId

		status, fixedUser, err = c.authPlugins.FixUserID(ctx, userID)
		if status != userpb.UserStatus_US_SUCCESS {
			return
		}

		userID = fixedUser

		var uid int64

		uid, err = c.m.GetUserIDBySource(userID.UserName, userID.UserVe)
		if err != nil {
			c.logger.Errorf(ctx, "GetUserIDBySource failed: %v", err)

			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}

		if uid <= 0 {
			c.logger.Errorf(ctx, "GetUserIDBySource no userID id: %+v", uid)

			status = userpb.UserStatus_US_USER_NOT_EXISTS

			return
		}

		ip := c.utils.GetPeerIP(ctx)

		var trust bool

		trust, err = c.m.IsUserTrust(uid, ip)
		if err != nil {
			c.logger.Errorf(ctx, "IsUserTrust failed: %v", err)

			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}

		if password == "" {
			c.logger.Errorf(ctx, "IsUserTrust check failed, need password verify")

			status = userpb.UserStatus_US_NEED_PASSWORD_AUTH

			return
		}

		if !trust {
			if codeForVe == "" {
				c.logger.Errorf(ctx, "IsUserTrust check failed, need code verify")

				status = userpb.UserStatus_US_NEED_VE_AUTH

				return
			}
		}

		if c.cfg.GoogleAuthenticator.Enable {
			var key string

			key, err = c.m.GetUser2FaKey(uid)
			if err != nil {
				c.logger.Errorf(ctx, "GetUser2FaKey failed: %v", err)

				status = userpb.UserStatus_US_INTERNAL_ERROR

				return
			}

			if codeForGa == "" {
				if key != "" {
					c.logger.Errorf(ctx, "should use 2fa: %v", uid)

					status = userpb.UserStatus_US_NEED_2FA_AUTH

					return
				}
			}
		}

		status, err = c.verifyPassword(ctx, uid, password)
		if status != userpb.UserStatus_US_SUCCESS {
			c.logger.Errorf(ctx, "check password failed: %v, %v", status, err)

			return
		}

		if codeForVe != "" {
			status, err = c.checkVe(userID, codeForVe)
			if status != userpb.UserStatus_US_SUCCESS {
				c.logger.Errorf(ctx, "check ve failed: %v, %v", status, err)

				return
			}
		}

		if codeForGa != "" {
			status = c.gaVerify(ctx, uid, codeForGa)
			if status != userpb.UserStatus_US_SUCCESS {
				c.logger.Errorf(ctx, "check 2fa failed: %v, %v", status, err)

				return
			}
		}

		var userInfo *user.UserInfo

		userInfo, err = c.m.GetUserInfo(uid)
		if err != nil {
			c.logger.Errorf(ctx, "get userID info failed: %v", err)

			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}

		err = c.m.UserTrustInc(userInfo.UserId, ip, 1)
		if err != nil {
			c.logger.Errorf(ctx, "trust inc failed: %v", err)
		}

		authInfo = c.dbUser2AuthInfo(userInfo)
	}

	ssoToken, token, info, err = c.signResponseInfoOnAuthInfo(ctx, authInfo, attachSsoToken, ssoJumpURL)
	if err != nil {
		c.logger.Errorf(ctx, "sign response info on auth info failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	if codeForVe != "" {
		c.removeVe(userID)
	}

	if c.cfg.GoogleAuthenticator.Force && !c.gaEnabled(ctx, authInfo.UserID) {
		status = userpb.UserStatus_US_NEED_2FA_SETUP
	} else {
		status = userpb.UserStatus_US_SUCCESS
	}

	return
}

func (c *Controller) SSOLogin(ctx context.Context, ssoToken string) (status userpb.UserStatus,
	token string, info *userpb.UserInfo, err error) {
	authInfo, err := c.verifySSOToken(ctx, ssoToken)
	if err != nil {
		c.logger.Errorf(ctx, "sso login failed: %v", err)

		status = userpb.UserStatus_US_WRONG_CODE

		return
	}

	_, token, info, err = c.signResponseInfoOnAuthInfo(ctx, authInfo, false, "")
	if err != nil {
		c.logger.Errorf(ctx, "sign response info on auth info failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) Logout(ctx context.Context, token string) (status userpb.UserStatus, err error) {
	status, fixedToken, _, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "fixAndVerifyToken failed: %v, %v", err, token)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	_ = c.removeToken(ctx, fixedToken)

	err = c.httpToken.UnsetUserTokenCookie(ctx, fixedToken)
	if err != nil {
		c.logger.Errorf(ctx, "unsetUserTokenCookie failed: %v", err)

		err = nil
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) GoogleAuthGetSetupInfo(ctx context.Context, token string) (status userpb.UserStatus,
	secretKey string, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "fixAndVerifyToken failed: %v, %v", err, token)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	secretKey, err = c.gaNewSecretQRCode(ctx, authInfo.UserID, authInfo.NickName)
	if err != nil {
		c.logger.Errorf(ctx, "generate secret qr code failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) GoogleAuthVerify(ctx context.Context, token, code string) (status userpb.UserStatus, gaToken string,
	err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	status = c.gaVerify(ctx, authInfo.UserID, code)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "ga verify failed: %v", status)

		return
	}

	gaToken, err = c.genGaToken(ctx, authInfo.UserID)
	if err != nil {
		status = userpb.UserStatus_US_INTERNAL_ERROR

		c.logger.Errorf(ctx, "gen ga token failed: %v", err)

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) GoogleAuthSet(ctx context.Context, token, code, tokenGaOld string) (status userpb.UserStatus,
	err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	if c.gaEnabled(ctx, authInfo.UserID) {
		if tokenGaOld == "" {
			status = userpb.UserStatus_US_NEED_2FA_AUTH

			return
		}
	}

	if tokenGaOld != "" {
		if !c.gaTokenExists(ctx, authInfo.UserID, tokenGaOld) {
			status = userpb.UserStatus_US_WRONG_CODE

			return
		}
	}

	if code == "" {
		if c.cfg.GoogleAuthenticator.Force {
			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}

		err = c.m.SetUser2FaKey(authInfo.UserID, "")

		if err != nil {
			status = userpb.UserStatus_US_INTERNAL_ERROR

			c.logger.Errorf(ctx, "db set google auth key failed: %v", err)
		}
	} else {
		status, err = c.gaSetupWithCode(ctx, authInfo.UserID, code)
	}

	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "gaSetupWithCode failed: %v, %v", status, err)

		return
	}

	if tokenGaOld != "" {
		c.removeGaToken(ctx, authInfo.UserID, tokenGaOld)
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) Profile(ctx context.Context, token string, attachSsoToken bool, ssoJumpURL string) (status userpb.UserStatus,
	userInfo *userpb.UserInfo, ssoToken string, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		return
	}

	if attachSsoToken {
		ssoToken, err = c.newSSOToken(ctx, authInfo.SessionID, authInfo, ssoJumpURL)
		if err != nil {
			c.logger.Errorf(ctx, "new sso token failed: %v", err)

			return
		}
	}

	gaEnabled := false

	if !authInfo.UserSourceIDFlag {
		gaEnabled = c.gaEnabled(ctx, authInfo.UserID)
	}

	userInfo = c.authInfo2PbUserInfo(authInfo, gaEnabled)

	status = userpb.UserStatus_US_SUCCESS

	return
}

// nolint: funlen
func (c *Controller) ResetPassword(ctx context.Context, user *userpb.UserId, newPassword, codeForVe,
	codeForGa string) (status userpb.UserStatus, token string, info *userpb.UserInfo, err error) {
	if user == nil || user.UserVe == "" {
		status = userpb.UserStatus_US_FAILED

		return
	}

	status, fixedUser, err := c.authPlugins.FixUserID(ctx, user)
	if status != userpb.UserStatus_US_SUCCESS {
		return
	}

	user = fixedUser

	status, err = c.checkVe(user, codeForVe)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "check ve failed: %v, %v", status, err)

		return
	}

	var userID int64

	userID, err = c.m.GetUserIDBySource(user.UserName, user.UserVe)
	if err != nil {
		c.logger.Errorf(ctx, "GetUserIDBySource failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	if userID <= 0 {
		c.logger.Errorf(ctx, "GetUserIDBySource no user id: %+v", user)

		status = userpb.UserStatus_US_USER_NOT_EXISTS

		return
	}

	if c.cfg.GoogleAuthenticator.Enable {
		var key string

		key, err = c.m.GetUser2FaKey(userID)
		if err != nil {
			c.logger.Errorf(ctx, "GetUser2FaKey failed: %v", err)

			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}

		if key != "" && codeForGa == "" {
			c.logger.Errorf(ctx, "should use 2fa: %v", userID)

			status = userpb.UserStatus_US_NEED_2FA_AUTH

			return
		}
	}

	if codeForGa != "" {
		status = c.gaVerify(ctx, userID, codeForGa)
		if status != userpb.UserStatus_US_SUCCESS {
			c.logger.Errorf(ctx, "check 2fa failed: %v, %v", status, err)

			return
		}
	}

	password, err := c.passEncrypt(newPassword)
	if err != nil {
		c.logger.Errorf(ctx, "pass encrypt failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	err = c.m.UpdateUserPassword(userID, password)
	if err != nil {
		c.logger.Errorf(ctx, "update user password failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status, token, info, err = c.signResponseInfoAfterCheckPass(ctx, userID, nil, 1)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "signResponseInfoAfterCheckPass failed: %v, %v", status, err)

		return
	}

	c.removeVe(user)

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) ChangePassword(ctx context.Context, token, csrfToken,
	password, newPassword string) (status userpb.UserStatus, newToken string, info *userpb.UserInfo, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	status, err = c.verifyPassword(ctx, authInfo.UserID, password)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "check password failed: %v, %v", status, err)

		return
	}

	status, err = c.verifyCsrfToken(ctx, csrfToken)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "check csrf token failed: %v, %v", status, err)

		return
	}

	encryptPassword, err := c.passEncrypt(newPassword)
	if err != nil {
		c.logger.Errorf(ctx, "pass encrypt failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	err = c.m.UpdateUserPassword(authInfo.UserID, encryptPassword)
	if err != nil {
		c.logger.Errorf(ctx, "update user password failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	return c.signResponseInfoAfterCheckPass(ctx, authInfo.UserID, nil, 1)
}

func (c *Controller) GetCsrfToken(ctx context.Context, token string) (
	status userpb.UserStatus, csrfToken string, err error) {
	status, token, _, err = c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS {
		return
	}

	csrfToken, err = c.genCsrfToken(ctx, token)
	if err != nil {
		c.logger.Errorf(ctx, "gen csrf token failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) GetDetailInfo(ctx context.Context, token string) (status userpb.UserStatus,
	info *userpb.UserDetailInfo, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	userDetail, userSource, err := c.m.GetUserDetailInfo(authInfo.UserID)
	if err != nil {
		c.logger.Errorf(ctx, "get user detail info failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	info = c.userDetail2PbUserDetail(userDetail, userSource)
	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) UpdateDetailInfo(ctx context.Context, token, csrfToken, avatar, nickName, phone, email, wechat string) (status userpb.UserStatus, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	status, err = c.verifyCsrfToken(ctx, csrfToken)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "check csrf token failed: %v, %v", status, err)

		return
	}

	err = c.m.UpdateUserInfo(authInfo.UserID, avatar, nickName)
	if err != nil {
		c.logger.Errorf(ctx, "update nick name failed: %v", err)

		status = userpb.UserStatus_US_USER_ALREADY_EXISTS

		return
	}

	err = c.m.UpdateUserExt(authInfo.UserID, phone, email, wechat)
	if err != nil {
		c.logger.Errorf(ctx, "update user ext failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) userDetail2PbUserDetail(userDetail *model.UserDetail, userSource *user.UserSource) *userpb.UserDetailInfo {
	var userID *userpb.UserId
	if userSource != nil {
		userID = &userpb.UserId{
			UserName: userSource.UserName,
			UserVe:   userSource.UserVe,
		}
	}

	return &userpb.UserDetailInfo{
		BaseInfo: &userpb.UserInfo{
			NickName:  userDetail.UserInfo.NickName,
			Avatar:    c.filterUserAvatar(userDetail.Avatar),
			EnabledGa: userDetail.UserAuthentication.Token2fa != "",
		},
		CreateAt: userDetail.UserInfo.CreateAt.Unix(),
		User:     userID,
		Phone:    userDetail.UserExt.Phone,
		Email:    userDetail.UserExt.Email,
		Wechat:   userDetail.UserExt.Wechat,
	}
}

func (c *Controller) fixAndVerifyToken(ctx context.Context, token string) (
	status userpb.UserStatus, fixedToken string, authInfo *AuthInfo, err error) {
	fixedToken = token
	if fixedToken == "" {
		fixedToken = c.getUserTokenCookie(ctx)
	}

	if fixedToken == "" {
		status = userpb.UserStatus_US_UNAUTHENTICATED

		return
	}

	authInfo, err = c.verifyToken(ctx, fixedToken)
	if err != nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_UNAUTHENTICATED

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) GetUserList(ctx context.Context, token, csrfToken string, offset int64, limit int32,
	keyword string) (status userpb.UserStatus, cnt int64, users []*userpb.UserListItem, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	status, err = c.verifyCsrfToken(ctx, csrfToken)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "check csrf token failed: %v, %v", status, err)

		return
	}

	adminUserInfo, err := c.m.GetUserInfo(authInfo.UserID)
	if err != nil {
		status = userpb.UserStatus_US_USER_NOT_EXISTS

		c.logger.Errorf(ctx, "admin user by id %v failed: %v", authInfo.UserID, err)

		return
	}

	if adminUserInfo.Privileges == 0 {
		status = userpb.UserStatus_US_DONT_SUPPORT

		c.logger.Warnf(ctx, "user %v no permission", authInfo.UserID)

		return
	}

	cnt, dbUsers, err := c.m.GetUserList(offset, int(limit), keyword)
	if err != nil {
		status = userpb.UserStatus_US_FAILED

		return
	}

	for _, dbUser := range dbUsers {
		gaEnabled := false

		if dbUser.UserSource.UserId > 0 {
			gaEnabled = c.gaEnabled(ctx, authInfo.UserID)
		}

		users = append(users, c.userItem2PbUserListItem(dbUser, gaEnabled))
	}

	return
}

func (c *Controller) ManagerUser(ctx context.Context, req *userpb.ManagerUserRequest) (status userpb.UserStatus, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, req.Token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	status, err = c.verifyCsrfToken(ctx, req.CsrfToken)
	if status != userpb.UserStatus_US_SUCCESS {
		c.logger.Errorf(ctx, "check csrf token failed: %v, %v", status, err)

		return
	}

	adminUserInfo, err := c.m.GetUserInfo(authInfo.UserID)
	if err != nil {
		status = userpb.UserStatus_US_USER_NOT_EXISTS

		c.logger.Errorf(ctx, "admin user by id %v failed: %v", req.Uid, err)

		return
	}

	userInfo, err := c.m.GetUserInfo(req.Uid)
	if err != nil {
		status = userpb.UserStatus_US_USER_NOT_EXISTS

		c.logger.Errorf(ctx, "search user by id %v failed: %v", req.Uid, err)

		return
	}

	if adminUserInfo.UserId == userInfo.UserId && req.Type == userpb.ManagerUserType_MUTDelete {
		status = userpb.UserStatus_US_INTERNAL_ERROR

		c.logger.Errorf(ctx, "try to kill self: %v", adminUserInfo.UserId)

		return
	}

	if adminUserInfo.Privileges == 0 {
		status = userpb.UserStatus_US_DONT_SUPPORT

		c.logger.Warnf(ctx, "user %v no permission", req.Uid)

		return
	}

	// nolint: nestif
	if req.Type == userpb.ManagerUserType_MUTSetAdminPrivilege {
		err = c.m.SetUserPrivileges(req.Uid, 1)
	} else if req.Type == userpb.ManagerUserType_MUTUnsetAdminPrivilege {
		err = c.m.SetUserPrivileges(req.Uid, 0)
	} else if req.Type == userpb.ManagerUserType_MUTDelete {
		err = c.m.DeleteUser(req.Uid)
	} else if req.Type == userpb.ManagerUserType_MUTSwitchAdminPrivilege {
		privileges := userInfo.Privileges
		if privileges == 0 {
			privileges = 1
		} else {
			privileges = 0
		}
		err = c.m.SetUserPrivileges(req.Uid, privileges)
	} else if req.Type == userpb.ManagerUserType_MUTResetPassword {
		if req.GetResetPassword() == nil {
			status = userpb.UserStatus_US_BAD_INPUT

			c.logger.Warn(ctx, "no reset password struct")

			return
		}
		var password string
		password, err = c.passEncrypt(req.GetResetPassword().NewPassword)
		if err != nil {
			c.logger.Errorf(ctx, "pass encrypt failed: %v", err)
			status = userpb.UserStatus_US_INTERNAL_ERROR

			return
		}
		err = c.m.UpdateUserPassword(req.Uid, password)
	}

	if err != nil {
		c.logger.Errorf(ctx, "mysql failed: %v", err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) AdminProfile(ctx context.Context, token string) (status userpb.UserStatus,
	userInfo *userpb.AdminUserInfo, err error) {
	status, _, authInfo, err := c.fixAndVerifyToken(ctx, token)
	if status != userpb.UserStatus_US_SUCCESS || authInfo == nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		status = userpb.UserStatus_US_BAD_INPUT

		return
	}

	gaEnabled := false
	if !authInfo.UserSourceIDFlag {
		gaEnabled = c.gaEnabled(ctx, authInfo.UserID)
	}

	userInfo = c.authInfo2PbAdminUserInfo(authInfo, gaEnabled)
	status = userpb.UserStatus_US_SUCCESS

	return
}
