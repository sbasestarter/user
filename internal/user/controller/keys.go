package controller

import (
	"fmt"
	"strings"

	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

const (
	keyCatAuthCode = "auth_code"
	keyCatAuthLock = "auth_lock"
)

func redisKeyForVeAuth(userName, category string) string {
	return strings.Join([]string{category, userName}, "_")
}

func redisUsername(user *userpb.UserId) string {
	return fmt.Sprintf("%v_%v", user.UserName, user.UserVe)
}

func redisKeyForSSOToken(userID int64, token string) string {
	return fmt.Sprintf("sso_token_%v_%v", userID, token)
}

func redisKeyForSession(userID int64, sessionID string) string {
	return fmt.Sprintf("session_id_%v_%v", userID, sessionID)
}

func redisKeyForGaToken(userID int64, token string) string {
	return fmt.Sprintf("ga_token_%v_%v", userID, token)
}

func redisKeyForCsrfToken(tokenSessionID string) string {
	return fmt.Sprintf("csrf_%s", tokenSessionID)
}

func redisKeyForSessionIDParent(parentSessionID string) string {
	return fmt.Sprintf("children:session_id:%v", parentSessionID)
}
