package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/issue9/assert"
)

func TestSSOToken(t *testing.T) {
	authInfo := &AuthInfo{
		UserSourceIDFlag: false,
		UserID:           1000,
	}
	token, err := TestController.newSSOToken(context.Background(), authInfo)
	assert.Nil(t, err)
	assert.True(t, token != "")

	authInfo2, err := TestController.verifySSOToken(context.Background(), token)
	assert.Nil(t, err)
	assert.True(t, authInfo2 != nil && authInfo2.UserID == authInfo.UserID)
}

func TestToken(t *testing.T) {
	authInfo := &AuthInfo{
		UserSourceIDFlag: false,
		UserID:           1000,
		ExpiresAt:        time.Now().Unix(),
	}
	token, err := TestController.generateToken(context.Background(), authInfo)
	assert.Nil(t, err)
	assert.True(t, token != "")
	authInfo2, err := TestController.verifyToken(context.Background(), token)
	assert.Nil(t, err)
	assert.True(t, authInfo2.UserID == authInfo.UserID)
}

func TestGenerateWhiteToken(t *testing.T) {
	authInfo := &AuthInfo{
		UserSourceIDFlag: true,
		UserID:           10000,
		NickName:         "testUser1",
	}
	tokenBin, err := json.Marshal(authInfo)
	assert.Nil(t, err)
	t.Log("token:", base64.StdEncoding.EncodeToString(tokenBin))
}
