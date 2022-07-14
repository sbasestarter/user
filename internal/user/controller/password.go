package controller

import (
	"context"

	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

func (c *Controller) verifyPassword(ctx context.Context, userID int64, password string) (userpb.UserStatus, error) {
	userAuth, err := c.m.GetUserAuthentication(userID)
	if err != nil {
		c.logger.Errorf(ctx, "user %v no auth info", userID)

		return userpb.UserStatus_USER_STATUS_INTERNAL_ERROR, err
	}

	if userAuth == nil || userAuth.Password == "" {
		c.logger.Errorf(ctx, "user %v no auth info: %v", userID, userAuth)

		return userpb.UserStatus_USER_STATUS_INTERNAL_ERROR, err
	}

	encryptedPassword, err := c.passEncrypt(password)
	if err != nil {
		return userpb.UserStatus_USER_STATUS_INTERNAL_ERROR, err
	}

	if userAuth.Password != encryptedPassword {
		return userpb.UserStatus_USER_STATUS_WRONG_PASSWORD, nil
	}

	return userpb.UserStatus_USER_STATUS_SUCCESS, nil
}
