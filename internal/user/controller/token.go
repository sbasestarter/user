package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/jiuzhou-zhao/go-fundamental/grpce"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/jiuzhou-zhao/go-fundamental/utils"
	"github.com/satori/go.uuid"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/pkg/user"
)

// AuthInfo class on token
type AuthInfo struct {
	UserSourceIDFlag bool
	UserID           int64
	NickName         string
	Avatar           string
	ExpiresAt        int64
	ClientIP         string
	CreateAt         int64
}

func (ai *AuthInfo) Valid() error {
	return nil
}

type TokenClaims struct {
	UserId    int64
	SessionId string
}

func (tc *TokenClaims) Valid() error {
	return nil
}

func (c *Controller) newSSOToken(ctx context.Context, u *AuthInfo) (string, error) {
	ssoToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, u).SignedString([]byte(c.cfg.Token.Secret))
	if err != nil {
		c.logger.Errorf(ctx, "new sso token jwt failed: %v", err)
		return "", err
	}
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, redisKeyForSSOToken(ssoToken), time.Now().String(), c.cfg.Token.SSOExpire).Result()
	})
	if err != nil {
		c.logger.Errorf(ctx, "new sso token redis failed: %v", err)
		return "", err
	}
	return ssoToken, nil
}

func (c *Controller) verifySSOToken(ctx context.Context, tokenString string) (*AuthInfo, error) {
	var info AuthInfo

	_, err := jwt.ParseWithClaims(tokenString, &info, func(token *jwt.Token) (interface{}, error) {
		return []byte(c.cfg.Token.Secret), nil
	})

	if err != nil {
		c.logger.Errorf(ctx, "verifySSOToken failed: %v", err)
		return nil, err
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Get(ctx, redisKeyForSSOToken(tokenString)).Result()
	})
	if err != nil {
		c.logger.Errorf(ctx, "verifySSOToken get redis failed: %v", err)
		return nil, err
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Del(ctx, redisKeyForSSOToken(tokenString)).Result()
	})
	if err != nil {
		c.logger.Warnf(ctx, "verifySSOToken del redis failed: %v", err)
	}

	return &info, nil
}

func (c *Controller) generateToken(ctx context.Context, u *AuthInfo) (string, error) {
	u.ClientIP = c.utils.GetPeerIp(ctx)
	u.ExpiresAt = time.Now().Add(c.cfg.Token.Expire).Unix()

	sessionId := uuid.NewV4().String()

	key := redisKeyForSession(u.UserID, sessionId)

	data, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, key, string(data), c.cfg.Token.Expire).Result()
	})
	if err != nil {
		return "", err
	}

	tc := &TokenClaims{
		UserId:    u.UserID,
		SessionId: sessionId,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, tc).SignedString([]byte(c.cfg.Token.Secret))
}

func (c *Controller) verifyToken(ctx context.Context, tokenString string) (*AuthInfo, error) {
	if ai, ok := c.whiteListTokens[tokenString]; ok {
		return ai, nil
	}

	var tc TokenClaims

	_, err := jwt.ParseWithClaims(tokenString, &tc, func(token *jwt.Token) (interface{}, error) {
		return []byte(c.cfg.Token.Secret), nil
	})

	if err != nil {
		c.logger.Errorf(ctx, "verifyToken failed: %v", err)
		return nil, err
	}

	key := redisKeyForSession(tc.UserId, tc.SessionId)
	var data string
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		data, err = c.redis.Get(ctx, key).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "get session failed: %v, %v", err, key)
		return nil, err
	}

	authInfo := &AuthInfo{}
	err = json.Unmarshal([]byte(data), authInfo)
	if err != nil {
		c.logger.Errorf(ctx, "unmarshal user info failed: %v, %v", err, data)
		return nil, err
	}

	if time.Now().Unix() > authInfo.ExpiresAt {
		err = fmt.Errorf("token timeout: %v, now is %v", time.Unix(authInfo.ExpiresAt, 0), time.Now())
		c.logger.Warnf(ctx, err.Error())
		return nil, err
	}
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Expire(ctx, key, c.cfg.Token.Expire).Result()
	})
	if err != nil {
		c.logger.Errorf(ctx, "set ttl of key %v failed: %v", key, err)
		err = nil
	}

	clientIP := c.utils.GetPeerIp(ctx)
	if !c.compareIP(ctx, authInfo.ClientIP, clientIP) {
		err = fmt.Errorf("ip miss: %v, now is %v", authInfo.ClientIP, clientIP)
		c.logger.Warnf(ctx, err.Error())
		return nil, err
	}

	return authInfo, nil
}

func (c *Controller) removeToken(ctx context.Context, tokenString string) error {
	var tc TokenClaims

	_, err := jwt.ParseWithClaims(tokenString, &tc, func(token *jwt.Token) (interface{}, error) {
		return []byte(c.cfg.Token.Secret), nil
	})

	if err != nil {
		c.logger.Errorf(ctx, "verifyToken failed: %v", err)
		return err
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		c.redis.Del(ctx, redisKeyForSession(tc.UserId, tc.SessionId))
	})
	return nil
}

func (c *Controller) compareIP(ctx context.Context, ip1, ip2 string) bool {
	netIP1 := net.ParseIP(ip1)
	netIP2 := net.ParseIP(ip2)
	if (netIP1 == nil && netIP2 != nil) || (netIP1 != nil && netIP2 == nil) {
		return false
	}
	if netIP1 == nil {
		return true
	}
	if netIP1.Equal(netIP2) {
		return true
	}

	loge.Warnf(ctx, "ip miss: %v, %v", netIP1.String(), netIP2.String())
	return false
}

func (c *Controller) getUserTokenCookie(ctx context.Context) string {
	return grpce.GetStringFromContext(ctx, user.SignCookieName)
}

func (c *Controller) genGaToken(ctx context.Context, userId int64) (token string, err error) {
	token = uuid.NewV4().String()
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, redisKeyForGaToken(userId, token), time.Now().String(), c.cfg.GoogleAuthenticator.TokenExpire).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "set redis key for ga token failed: %v", err)
		return
	}
	return
}

func (c *Controller) gaTokenExists(ctx context.Context, userId int64, token string) bool {
	key := redisKeyForGaToken(userId, token)
	var err error
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Get(ctx, key).Result()
	})

	if err != nil {
		if err != redis.Nil {
			c.logger.Errorf(ctx, "redis %v err: %v", key, err)
		}
		return false
	}
	return true
}

func (c *Controller) removeGaToken(ctx context.Context, userId int64, token string) {
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		c.redis.Del(ctx, redisKeyForGaToken(userId, token))
	})
}

func (c *Controller) genCsrfToken(ctx context.Context, token string) (string, error) {
	tokenSessionId := uuid.NewV4().String()
	key := redisKeyForCsrfToken(tokenSessionId)
	var err error
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, key, token, c.cfg.CsrfExpire).Result()
	})
	if err != nil {
		c.logger.Errorf(ctx, "set redis %v failed: %v", key, err)
		return "", err
	}
	return tokenSessionId, err
}

func (c *Controller) verifyCsrfToken(ctx context.Context, csrfToken string) (userpb.UserStatus, error) {
	key := redisKeyForCsrfToken(csrfToken)
	var token string
	var err error
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		token, err = c.redis.Get(ctx, key).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "redis no key: %v", err)
		return userpb.UserStatus_US_WRONG_CODE, err
	}
	_, err = c.verifyToken(ctx, token)
	if err != nil {
		c.logger.Errorf(ctx, "redis invalid token: %v", err)
		return userpb.UserStatus_US_WRONG_CODE, err
	}
	return userpb.UserStatus_US_SUCCESS, nil
}

func (c *Controller) removeCsrfToken(_ context.Context, csrfToken string) {
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		c.redis.Del(ctx, redisKeyForCsrfToken(csrfToken))
	})
}
