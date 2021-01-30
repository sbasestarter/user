package model

import (
	"testing"

	"github.com/issue9/assert"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

const (
	TestGaKey           = "121212"
	TestAddUserName     = "user_name"
	TestAddUserVe       = "user_ve"
	TestAddUserPass     = "pass"
	TestAddUserNickname = "nick_name"
	TestAddUserAvatar   = "avatar"
	TestIP1             = "127.0.0.1"
	TestIP2             = "127.0.0.2"
)

func Test2Fa(t *testing.T) {
	key, err := TestModel.GetUser2FaKey(TestUserId)
	assert.Nil(t, err)
	assert.True(t, key == "")

	err = TestModel.SetUser2FaKey(TestUserId, TestGaKey)
	assert.Nil(t, err)

	key, err = TestModel.GetUser2FaKey(TestUserId)
	assert.Nil(t, err)
	assert.True(t, key == TestGaKey)
}

func TestModel_User(t *testing.T) {
	status, userInfo, err := TestModel.NewUser(TestAddUserName, TestAddUserVe, TestAddUserPass, TestAddUserNickname, TestAddUserAvatar)
	assert.True(t, status == userpb.UserStatus_US_SUCCESS)
	assert.True(t, userInfo != nil && userInfo.UserId > 0 && userInfo.Avatar == TestAddUserAvatar && userInfo.NickName == TestAddUserNickname)
	assert.Nil(t, err)
	userInfo, err = TestModel.GetUserInfo(userInfo.UserId)
	assert.Nil(t, err)
	assert.True(t, userInfo != nil && userInfo.UserId > 0 && userInfo.Avatar == TestAddUserAvatar && userInfo.NickName == TestAddUserNickname)
	userAuth, err := TestModel.GetUserAuthentication(userInfo.UserId)
	assert.Nil(t, err)
	assert.True(t, userAuth != nil && userAuth.Password == TestAddUserPass)
	uid, err := TestModel.GetUserIDBySource(TestAddUserName, TestAddUserVe)
	assert.Nil(t, err)
	assert.True(t, uid == userInfo.UserId)

	err = TestModel.UserTrustInc(uid, TestIP1, 5)
	assert.Nil(t, err)
	pass, err := TestModel.IsUserTrust(uid, TestIP1)
	assert.Nil(t, err)
	assert.False(t, pass)
	err = TestModel.UserTrustInc(uid, TestIP1, 1)
	assert.Nil(t, err)
	pass, err = TestModel.IsUserTrust(uid, TestIP1)
	assert.Nil(t, err)
	assert.True(t, pass)
	pass, err = TestModel.IsUserTrust(uid, TestIP2)
	assert.Nil(t, err)
	assert.False(t, pass)
}
