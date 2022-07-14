package controller

import (
	"strconv"

	"github.com/sbasestarter/db-orm/go/user"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/user/model"
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

func (c *Controller) userInfo2PbUserInfo(aInfo *user.UserInfo, gaEnabled bool) *userpb.UserInfo {
	flagGa := userpb.GoogleAuthGlobalFlag_GoogleAuthNone
	if c.cfg.GoogleAuthenticator.Enable {
		flagGa = userpb.GoogleAuthGlobalFlag_GoogleAuthFlagEnabled

		if c.cfg.GoogleAuthenticator.Force {
			flagGa = userpb.GoogleAuthGlobalFlag_GoogleAuthFlagEnabledForce
		}
	}

	return &userpb.UserInfo{
		Id:        strconv.FormatInt(aInfo.UserId, 10),
		NickName:  aInfo.NickName,
		Avatar:    c.filterUserAvatar(aInfo.Avatar),
		EnabledGa: gaEnabled,
		FlagGa:    flagGa,
	}
}

func (c *Controller) userItem2PbUserListItem(item *model.UserItem, gaEnabled bool) *userpb.UserListItem {
	return &userpb.UserListItem{
		User: &userpb.UserId{
			UserName: item.UserSource.UserName,
			UserVe:   item.UserSource.UserVe,
		},
		Info:        c.userInfo2PbUserInfo(&item.UserInfo, gaEnabled),
		CreateAt:    item.UserInfo.CreateAt.String(),
		LastLoginAt: "",
		Privileges:  int64(item.UserInfo.Privileges),
	}
}
