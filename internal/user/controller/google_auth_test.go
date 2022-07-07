package controller

import (
	"context"
	"testing"
	"time"

	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/utils"
	"github.com/sgostarter/libeasygo/authenticator"
	"github.com/stretchr/testify/assert"
)

func TestGoogleAuth(t *testing.T) {
	t.SkipNow()

	var userId int64 = 1000
	qrCode, err := TestController.gaNewSecretQRCode(context.Background(), userId, "test_user")
	assert.Nil(t, err)
	assert.True(t, len(qrCode) > 0)

	var key string
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		key, err = TestToolset.GetRedis().Get(ctx, gaSecretKeyRedisKey(userId)).Result()
	})
	assert.Nil(t, err)
	expect, err := authenticator.MakeGoogleAuthenticatorForNow(key)
	assert.Nil(t, err)

	st, err := TestController.gaSetupWithCode(context.Background(), userId, expect)
	assert.Nil(t, err)
	assert.True(t, st == userpb.UserStatus_US_SUCCESS)

	time.Sleep(31 * time.Second)

	expect2, err := authenticator.MakeGoogleAuthenticatorForNow(key)
	assert.Nil(t, err)

	assert.True(t, expect != expect2)

	st = TestController.gaVerify(context.Background(), userId, expect2)
	assert.True(t, st == userpb.UserStatus_US_SUCCESS)

}
