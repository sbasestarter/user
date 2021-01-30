package controller

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/jiuzhou-zhao/go-fundamental/utils"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

func (c *Controller) checkVe(user *userpb.UserId, code string) (userpb.UserStatus, error) {
	key := redisKeyForVeAuth(redisUsername(user), keyCatAuthCode)

	var verifyCodeInDB string
	var err error
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		verifyCodeInDB, err = c.redis.Get(ctx, key).Result()
	})
	if err != nil {
		if err == redis.Nil {
			err = fmt.Errorf("verify ve expired: %v", err)
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
