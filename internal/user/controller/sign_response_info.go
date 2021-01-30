package controller

import (
	"context"

	"github.com/sbasestarter/db-orm/go/user"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

func (c *Controller) signResponseInfoAfterCheckPass(ctx context.Context, userId int64, userInfo *user.UserInfo,
	incTrustNum int) (status userpb.UserStatus, token string, info *userpb.UserInfo,
	err error) {
	status, _, token, info, err = c.signResponseInfoAfterCheckPassEx(ctx, userId, userInfo, incTrustNum,
		false)
	return
}

func (c *Controller) signResponseInfoAfterCheckPassEx(ctx context.Context, userId int64, userInfo *user.UserInfo,
	incTrustNum int, attachSsoToken bool) (status userpb.UserStatus, ssoToken, token string, info *userpb.UserInfo,
	err error) {

	if userInfo == nil {
		userInfo, err = c.m.GetUserInfo(userId)
		if err != nil {
			c.logger.Errorf(ctx, "get user info failed: %v", err)
			status = userpb.UserStatus_US_INTERNAL_ERROR
			return
		}
	}

	ip := c.utils.GetPeerIp(ctx)
	err = c.m.UserTrustInc(userInfo.UserId, ip, incTrustNum)
	if err != nil {
		c.logger.Errorf(ctx, "trust inc failed: %v", err)
		err = nil
	}
	authInfo := c.dbUser2AuthInfo(userInfo)
	ssoToken, token, info, err = c.signResponseInfoOnAuthInfo(ctx, authInfo, attachSsoToken)
	if err != nil {
		c.logger.Errorf(ctx, "sign response info on auth info failed: %v", err)
		status = userpb.UserStatus_US_INTERNAL_ERROR
		return
	}

	status = userpb.UserStatus_US_SUCCESS
	return
}

func (c *Controller) signResponseInfoOnAuthInfo(ctx context.Context, auth *AuthInfo,
	attachSsoToken bool) (ssoToken, token string, info *userpb.UserInfo, err error) {
	if attachSsoToken {
		ssoToken, err = c.newSSOToken(ctx, auth)
		if err != nil {
			c.logger.Errorf(ctx, "new sso token failed: %v", err)
			return
		}
	}

	token, err = c.generateToken(ctx, auth)
	if err != nil {
		c.logger.Errorf(ctx, "generate token failed: %v", err)
		return
	}

	err = c.httpToken.SetUserTokenCookie(ctx, token)
	if err != nil {
		c.logger.Errorf(ctx, "setUserTokenCookie failed: %v", err)
		err = nil
	}

	gaEnabled := false
	if !auth.UserSourceIDFlag {
		gaEnabled = c.gaEnabled(ctx, auth.UserID)
	}
	info = c.authInfo2PbUserInfo(auth, gaEnabled)
	return
}
