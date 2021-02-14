package controller

import (
	"fmt"
	"strings"

	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

const (
	keyCatAuthCode = "auth_code"
	keyCatAuthLock = "auth_lock"
)

func redisKeyForVeAuth(userName, category string, args ...string) string {
	return strings.Join(append([]string{category, userName}, args...), "_")
}

func redisUsername(user *userpb.UserId) string {
	return fmt.Sprintf("%v_%v", user.UserName, user.UserVe)
}

func redisKeyForSSOToken(userId int64, token string) string {
	return fmt.Sprintf("sso_token_%v_%v", userId, token)
}

func redisKeyForSession(userId int64, sessionId string) string {
	return fmt.Sprintf("session_id_%v_%v", userId, sessionId)
}

func redisKeyForGaToken(userId int64, token string) string {
	return fmt.Sprintf("ga_token_%v_%v", userId, token)
}

func redisKeyForCsrfToken(tokenSessionId string) string {
	return fmt.Sprintf("csrf_%v", tokenSessionId)
}

func redisKeyForSessionIDParent(parentSessionID string) string {
	return fmt.Sprintf("children:session_id:%v", parentSessionID)
}
