package controller

import (
	"github.com/sbasestarter/db-orm/go/user"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

func (c *Controller) dbUser2AuthInfo(user *user.UserInfo) *AuthInfo {
	return &AuthInfo{
		UserSourceIDFlag: false,
		UserID:           user.UserId,
		NickName:         user.NickName,
		Avatar:           c.filterUserAvatar(user.Avatar),
		CreateAt:         user.CreateAt.Unix(),
	}
}

func (c *Controller) authInfo2PbUserInfo(aInfo *AuthInfo, gaEnabled bool) *userpb.UserInfo {
	flagGa := userpb.GoogleAuthGlobalFlag_GoogleAuthNone
	if c.cfg.GoogleAuthenticator.Enable {
		flagGa = userpb.GoogleAuthGlobalFlag_GoogleAuthFlagEnabled
		if c.cfg.GoogleAuthenticator.Force {
			flagGa = userpb.GoogleAuthGlobalFlag_GoogleAuthFlagEnabledForce
		}
	}
	return &userpb.UserInfo{
		NickName:  aInfo.NickName,
		Avatar:    c.filterUserAvatar(aInfo.Avatar),
		EnabledGa: gaEnabled,
		FlagGa:    flagGa,
	}
}

func (c *Controller) authInfo2PbAdminUserInfo(aInfo *AuthInfo, gaEnabled bool) *userpb.AdminUserInfo {
	return &userpb.AdminUserInfo{
		Id:        aInfo.UserID,
		NickName:  aInfo.NickName,
		Avatar:    c.filterUserAvatar(aInfo.Avatar),
		EnabledGa: gaEnabled,
	}
}
