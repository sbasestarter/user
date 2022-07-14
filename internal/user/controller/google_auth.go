package controller

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"

	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/utils"
	"github.com/sgostarter/libeasygo/authenticator"
	"golang.org/x/crypto/bcrypt"
)

func gaSecretKeyRedisKey(userID int64) string {
	return fmt.Sprintf("ga_key_%v", userID)
}

func (c *Controller) gaNewSecretQRCode(ctx context.Context, userID int64, userName string) (qrCode string, err error) {
	key, err := genGoogleAuthKey()
	if err != nil {
		c.logger.Errorf(ctx, "genGoogleAuthKey failed: %v", err)

		return
	}

	keyExpire := c.cfg.GoogleAuthenticator.KeyExpire

	c.logger.Infof(ctx, "key expire %v", keyExpire)

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, gaSecretKeyRedisKey(userID), key, keyExpire).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "redis error: %v", err)

		return
	}

	qrCode = authenticator.CreateGoogleAuthQRCodeData(key, userName, c.cfg.GoogleAuthenticator.Issuer)

	return
}

func (c *Controller) gaSetupWithCode(ctx context.Context, userID int64, code string) (status userpb.UserStatus, err error) {
	var key string

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		key, err = c.redis.Get(ctx, gaSecretKeyRedisKey(userID)).Result()
	})

	if err != nil {
		status = userpb.UserStatus_US_INTERNAL_ERROR

		c.logger.Errorf(ctx, "get redis value failed: %v, %v", err, gaSecretKeyRedisKey(userID))

		return
	}

	ok, err := validateUser2FaCode(key, code)
	if err != nil {
		status = userpb.UserStatus_US_INTERNAL_ERROR

		c.logger.Errorf(ctx, "validateUser2FaCode error: %v, %v", err, code)

		return
	}

	if !ok {
		status = userpb.UserStatus_US_WRONG_CODE
		err = fmt.Errorf("validateUser2FaCode failed: %v", code)

		c.logger.Errorf(ctx, err.Error())

		return
	}

	err = c.m.SetUser2FaKey(userID, key)
	if err != nil {
		status = userpb.UserStatus_US_INTERNAL_ERROR

		c.logger.Errorf(ctx, "db set google auth key failed: %v", err)

		return
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Del(ctx, gaSecretKeyRedisKey(userID)).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "del %v failed: %v", gaSecretKeyRedisKey(userID), err)

		status = userpb.UserStatus_US_INTERNAL_ERROR

		return
	}

	status = userpb.UserStatus_US_SUCCESS

	return
}

func (c *Controller) gaVerify(ctx context.Context, userID int64, code string) userpb.UserStatus {
	key, err := c.m.GetUser2FaKey(userID)
	if err != nil {
		c.logger.Errorf(ctx, "user %v: %v", userID, err)

		return userpb.UserStatus_US_FAILED
	}

	if key == "" {
		return userpb.UserStatus_US_NEED_2FA_SETUP
	}

	ok, err := validateUser2FaCode(key, code)
	if err != nil {
		c.logger.Errorf(ctx, "validateUser2FaCode failed: %v", err)

		return userpb.UserStatus_US_INTERNAL_ERROR
	}

	if !ok {
		return userpb.UserStatus_US_WRONG_CODE
	}

	return userpb.UserStatus_US_SUCCESS
}

func (c *Controller) gaEnabled(ctx context.Context, userID int64) bool {
	userAuth, err := c.m.GetUserAuthentication(userID)
	if err != nil {
		c.logger.Errorf(ctx, "get user auth failed: %v", err)

		return false
	}

	if userAuth == nil {
		return false
	}

	return userAuth.Token2fa != ""
}

//
//
//

func genGoogleAuthKey() (key string, err error) {
	b := make([]byte, 6)

	_, err = rand.Read(b)
	if err != nil {
		return
	}

	keyBytes, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		return
	}

	key = base32.StdEncoding.EncodeToString(keyBytes)

	return
}

func validateUser2FaCode(key string, code string) (ok bool, err error) {
	expect, err := authenticator.MakeGoogleAuthenticatorForNow(key)
	if err != nil {
		return
	}

	return expect == code, nil
}
