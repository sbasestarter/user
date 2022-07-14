package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-redis/redis/v8"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/utils"
)

func (c *Controller) checkVe(user *userpb.UserId, code string) (userpb.UserStatus, error) {
	key := redisKeyForVeAuth(redisUsername(user), keyCatAuthCode)

	var verifyCodeInDB string

	var err error

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		verifyCodeInDB, err = c.redis.Get(ctx, key).Result()
	})

	if err != nil {
		if errors.Is(err, redis.Nil) {
			err = fmt.Errorf("verify ve expired: %w", err)

			return userpb.UserStatus_US_WRONG_CODE, err
		}

		return userpb.UserStatus_US_INTERNAL_ERROR, err
	}

	if verifyCodeInDB != code {
		return userpb.UserStatus_US_WRONG_CODE, nil
	}

	return userpb.UserStatus_US_SUCCESS, nil
}

func (c *Controller) removeVe(user *userpb.UserId) {
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		c.redis.Del(ctx, redisKeyForVeAuth(redisUsername(user), keyCatAuthCode))
	})
}
