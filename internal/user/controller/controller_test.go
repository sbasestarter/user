package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/issue9/assert"
	"github.com/jiuzhou-zhao/go-fundamental/authenticator"
	"github.com/jiuzhou-zhao/go-fundamental/utils"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

func fakeRegisterUser(t *testing.T) string {
	return fakeRegisterUserById(TestUserId, t)
}

func fakeRegisterUserById(user *userpb.UserId, t *testing.T) string {
	status, err := TestController.TriggerAuth(context.Background(), user, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, info, ssoToken, err := TestController.Register(context.Background(), user, "12312",
		"123456", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	t.Log(token, info, ssoToken)
	assert.Nil(t, err)
	return token
}

func TestTriggerAuth(t *testing.T) {
	TCasePre()

	status, err := TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.True(t, status == userpb.UserStatus_US_SUCCESS)

	status, err = TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.True(t, status == userpb.UserStatus_US_VERIFY_TOO_QUICK)

	userId2 := &userpb.UserId{
		UserName: "abcd@qq.com",
		UserVe:   userpb.VerificationEquipment_VECustom.String(),
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(userId2), keyCatAuthLock))
	})

	status, err = TestController.TriggerAuth(context.Background(), userId2, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.True(t, status == userpb.UserStatus_US_DONT_SUPPORT)

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(userId2), keyCatAuthLock))
	})
}

func TestRegisterLogin(t *testing.T) {
	TCasePre()

	status, _, _, _, _ := TestController.Register(context.Background(), TestUserId, "12312",
		"123456", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_WRONG_CODE)

	status, err := TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, info, ssoToken, err := TestController.Register(context.Background(), TestUserId, "12312",
		"123456", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	t.Log(token, info, ssoToken)
	assert.Nil(t, err)

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
	})
	status, err = TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, info, ssoToken, err = TestController.Register(context.Background(), TestUserId, "12312",
		"123456", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_USER_ALREADY_EXISTS)
	assert.Nil(t, err)
	t.Log(token)
	t.Log(info)
	t.Log(ssoToken)

	status, token, info, ssoToken, err = TestController.Login(context.Background(), TestUserId, "123456", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	t.Log(token)
	t.Log(info)
	t.Log(ssoToken)

	TestPeerIp = "127.0.0.2"
	for idx := 0; idx < 6; idx++ { // to model's UserTrustRegisterNumber
		status, token, info, ssoToken, err = TestController.Login(context.Background(), TestUserId, "123456", "",
			"", false, "")
		assert.Equal(t, status, userpb.UserStatus_US_NEED_VE_AUTH)
		assert.Nil(t, err)
		t.Log(token)
		t.Log(info)
		t.Log(ssoToken)

		utils.DefRedisTimeoutOp(func(ctx context.Context) {
			TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
		})
		status, err = TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
		assert.Nil(t, err)
		assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

		status, token, info, ssoToken, err = TestController.Login(context.Background(), TestUserId, "123456",
			"12312", "", false, "")
		assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
		assert.Nil(t, err)
		t.Log(token)
		t.Log(info)
		t.Log(ssoToken)
	}
	status, token, info, ssoToken, err = TestController.Login(context.Background(), TestUserId, "123456", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	t.Log(token)
	t.Log(info)
	t.Log(ssoToken)
}

func TestGa(t *testing.T) {
	TCasePre()

	token := fakeRegisterUser(t)

	status, key, err := TestController.GoogleAuthGetSetupInfo(context.Background(), token)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)

	sp := "secret="
	idx1 := strings.Index(key, sp) + len(sp)
	idx2 := strings.LastIndex(key, "&")
	secret := key[idx1:idx2]

	for retry := 0; retry <= 1; retry++ {
		expect, err := authenticator.MakeGoogleAuthenticatorForNow(secret)
		assert.Nil(t, err)
		status, err = TestController.GoogleAuthSet(context.Background(), token, expect, "")
		if status == userpb.UserStatus_US_SUCCESS {
			break
		}
		assert.Nil(t, err)
	}
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)

	//
	status, key, err = TestController.GoogleAuthGetSetupInfo(context.Background(), token)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)

	idx1 = strings.Index(key, sp) + len(sp)
	idx2 = strings.LastIndex(key, "&")
	secret2 := key[idx1:idx2]
	expect2, err := authenticator.MakeGoogleAuthenticatorForNow(secret2)
	assert.Nil(t, err)

	status, err = TestController.GoogleAuthSet(context.Background(), token, expect2, "")
	assert.Equal(t, status, userpb.UserStatus_US_NEED_2FA_AUTH)
	assert.Nil(t, err)

	expect, err := authenticator.MakeGoogleAuthenticatorForNow(secret)
	assert.Nil(t, err)

	var gaToken string
	for retry := 0; retry <= 1; retry++ {
		status, gaToken, err = TestController.GoogleAuthVerify(context.Background(), token, expect)
		if status == userpb.UserStatus_US_SUCCESS {
			assert.Nil(t, err)
			break
		}
	}
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	for retry := 0; retry <= 1; retry++ {
		expect2, err = authenticator.MakeGoogleAuthenticatorForNow(secret2)
		assert.Nil(t, err)
		status, err = TestController.GoogleAuthSet(context.Background(), token, expect2, gaToken)
		if status == userpb.UserStatus_US_SUCCESS {
			assert.Nil(t, err)
			break
		}
	}
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "123456", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_NEED_2FA_AUTH)

	for retry := 0; retry <= 1; retry++ {
		expect2, err = authenticator.MakeGoogleAuthenticatorForNow(secret2)
		assert.Nil(t, err)
		status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "123456", "",
			expect2, false, "")
		if status == userpb.UserStatus_US_SUCCESS {
			break
		}
	}
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
}

func TestGa2(t *testing.T) {
	TCasePre()

	TestCfg.GoogleAuthenticator.Force = true

	fakeRegisterUser(t)

	status, _, _, _, _ := TestController.Login(context.Background(), TestUserId, "123456", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_NEED_2FA_SETUP)
}

func TestSSOLogin1(t *testing.T) {
	TCasePre()

	status, err := TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, info, ssoToken, err := TestController.Register(context.Background(), TestUserId, "12312",
		"123456", true, "a.cn")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	t.Log(token, info, ssoToken)
	assert.Nil(t, err)

	status, token, _, err = TestController.SSOLogin(context.Background(), ssoToken)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	assert.True(t, token != "")
}

func TestSSOLogin2(t *testing.T) {
	TCasePre()

	fakeRegisterUser(t)

	status, _, _, ssoToken, _ := TestController.Login(context.Background(), TestUserId, "123456", "",
		"", true, "a.cn")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, _, err := TestController.SSOLogin(context.Background(), ssoToken)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	assert.True(t, token != "")
	assert.True(t, token != "")
	status, userInfo, _, err := TestController.Profile(context.Background(), token, false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	assert.True(t, userInfo != nil)
	assert.True(t, token != "")

	status, err = TestController.Logout(context.Background(), token)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
}

func TestController_ResetPassword(t *testing.T) {
	TCasePre()

	fakeRegisterUser(t)

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
	})
	status, err := TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, info, err := TestController.ResetPassword(context.Background(), TestUserId,
		"123456789", "12312", "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	assert.True(t, token != "")
	assert.True(t, info != nil)

	status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "123456789", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	TestCfg.GoogleAuthenticator.Force = true

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		TestController.redis.Del(ctx, redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
	})
	status, err = TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, info, err = TestController.ResetPassword(context.Background(), TestUserId,
		"1", "12312", "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)
	assert.True(t, token != "")
	assert.True(t, info != nil)

	status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "1", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_NEED_2FA_SETUP)

	//
	status, key, err := TestController.GoogleAuthGetSetupInfo(context.Background(), token)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)

	sp := "secret="
	idx1 := strings.Index(key, sp) + len(sp)
	idx2 := strings.LastIndex(key, "&")
	secret := key[idx1:idx2]

	for retry := 0; retry <= 1; retry++ {
		expect, err := authenticator.MakeGoogleAuthenticatorForNow(secret)
		assert.Nil(t, err)
		status, _ = TestController.GoogleAuthSet(context.Background(), token, expect, "")
		if status == userpb.UserStatus_US_SUCCESS {
			break
		}
	}
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
	assert.Nil(t, err)

	status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "1", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_NEED_2FA_AUTH)

	for retry := 0; retry <= 1; retry++ {
		expect, err := authenticator.MakeGoogleAuthenticatorForNow(secret)
		assert.Nil(t, err)
		status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "1", "",
			expect, false, "")
		if status == userpb.UserStatus_US_SUCCESS {
			break
		}
	}
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
}

func TestController_ChangePassword(t *testing.T) {
	TCasePre()

	fakeRegisterUser(t)

	TestController.redis.Del(context.Background(), redisKeyForVeAuth(redisUsername(TestUserId), keyCatAuthLock))
	status, err := TestController.TriggerAuth(context.Background(), TestUserId, userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister)
	assert.Nil(t, err)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, token, _, _, _ := TestController.Login(context.Background(), TestUserId, "123456", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, _, _, _ = TestController.ChangePassword(context.Background(), token, "", "123456", "1")
	assert.Equal(t, status, userpb.UserStatus_US_WRONG_CODE)

	status, csrfToken, _ := TestController.GetCsrfToken(context.Background(), token)
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, _, _, _ = TestController.ChangePassword(context.Background(), token, csrfToken, "123456", "1")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)

	status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "123456", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_WRONG_PASSWORD)

	status, _, _, _, _ = TestController.Login(context.Background(), TestUserId, "1", "",
		"", false, "")
	assert.Equal(t, status, userpb.UserStatus_US_SUCCESS)
}

func TestRegisterMany(t *testing.T) {
	t.SkipNow()

	TCasePre()

	userIds := make([]*userpb.UserId, 0, 1000)
	for idx := 0; idx < 1000; idx++ {
		userIds = append(userIds, &userpb.UserId{
			UserName: fmt.Sprintf("TestUser%v@qq.com", idx),
			UserVe:   "VEMail",
		})
	}

	idx := 0
	for {
		fakeRegisterUserById(userIds[idx], t)
		idx++
		if idx >= len(userIds) {
			break
		}
		<-time.After(2 * time.Second)
	}
}
