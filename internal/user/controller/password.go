package controller

import (
	"context"

	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

func (c *Controller) verifyPassword(ctx context.Context, userId int64, password string) (userpb.UserStatus, error) {
	userAuth, err := c.m.GetUserAuthentication(userId)
	if err != nil {
		c.logger.Errorf(ctx, "user %v no auth info", userId)
		return userpb.UserStatus_US_INTERNAL_ERROR, err
	}
	if userAuth == nil || userAuth.Password == "" {
		c.logger.Errorf(ctx, "user %v no auth info: %v", userId, userAuth)
		return userpb.UserStatus_US_INTERNAL_ERROR, err
	}

	encryptedPassword, err := c.passEncrypt(password)
	if err != nil {
		return userpb.UserStatus_US_INTERNAL_ERROR, err
	}
	if userAuth.Password != encryptedPassword {
		return userpb.UserStatus_US_WRONG_PASSWORD, nil
	}
	return userpb.UserStatus_US_SUCCESS, nil
}
