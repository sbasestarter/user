package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	uuid "github.com/satori/go.uuid"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/utils"
	"github.com/sbasestarter/user/pkg/user"
	"github.com/sgostarter/libservicetoolset/grpce"
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
	ParentSessionID  string
	SessionID        string

	ExpiresAtString string
	CreateAtString  string
}

func (ai *AuthInfo) Valid() error {
	return nil
}

type TokenClaims struct {
	UserID    int64
	SessionID string
}

func (tc *TokenClaims) Valid() error {
	return nil
}

func (c *Controller) checkSSOJumpURL(ctx context.Context, ssoJumpURL string) (valid bool, err error) {
	if ssoJumpURL == "" {
		err = errors.New("no jump url")
		c.logger.Error(ctx, err)

		return
	}

	u, err := url.Parse(ssoJumpURL)
	if err != nil {
		c.logger.Errorf(ctx, "parse url %v failed: %v", ssoJumpURL, err)

		return
	}

	if u == nil || u.Host == "" {
		err = errors.New("url or host is empty")
		c.logger.Error(ctx, err)

		return
	}

	if _, ok := c.cfg.WhiteListSSOJumpDomainMap[u.Host]; !ok {
		for _, match := range c.cfg.WhiteListSSOJumpDomainMatch {
			if strings.HasSuffix(u.Host, match) {
				valid = true

				break
			}
		}
	} else {
		valid = true
	}

	return
}

func (c *Controller) newSSOToken(ctx context.Context, parentSessionID string, u *AuthInfo, ssoJumpURL string) (string, error) {
	ok, err := c.checkSSOJumpURL(ctx, ssoJumpURL)
	if err != nil {
		return "", err
	}

	if !ok {
		return "", errors.New("invalid sso jump url")
	}

	sessionID := uuid.NewV4().String()
	u.ParentSessionID = parentSessionID

	return c.generateTokenEx(ctx, sessionID, redisKeyForSSOToken(u.UserID, sessionID), c.cfg.Token.Expire, u)
}

func (c *Controller) verifySSOToken(ctx context.Context, tokenString string) (authInfo *AuthInfo, err error) {
	redisKey, authInfo, err := c.verifyTokenEx(ctx, redisKeyForSSOToken, tokenString)
	if err != nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		return
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Del(ctx, redisKey).Result()
	})

	if err != nil {
		c.logger.Warnf(ctx, "set ttl of key %v failed: %v", redisKey, err)

		err = nil
	}

	return
}

func (c *Controller) generateToken(ctx context.Context, u *AuthInfo) (sessionID string, token string, err error) {
	sessionID = uuid.NewV4().String()

	token, err = c.generateTokenEx(ctx, sessionID, redisKeyForSession(u.UserID, sessionID), c.cfg.Token.Expire, u)

	if u.ParentSessionID != "" {
		utils.DefRedisTimeoutOp(func(ctx context.Context) {
			c.redis.SAdd(ctx, redisKeyForSessionIDParent(u.ParentSessionID), sessionID)
		})
	}

	return
}

func (c *Controller) generateTokenEx(ctx context.Context, sessionID string, redisKey string, redisExpire time.Duration,
	u *AuthInfo) (string, error) {
	u.ClientIP = c.utils.GetPeerIP(ctx)
	u.ExpiresAt = time.Now().Add(c.cfg.Token.Expire).Unix()
	u.SessionID = sessionID
	u.ExpiresAtString = time.Unix(u.ExpiresAt, 0).String()
	u.CreateAtString = time.Unix(u.CreateAt, 0).String()

	data, err := json.Marshal(u)
	if err != nil {
		c.logger.Errorf(ctx, "marshal auth info failed: %v", err)

		return "", err
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, redisKey, string(data), redisExpire).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "set redis for %v failed: %v", redisKey, err)

		return "", err
	}

	tc := &TokenClaims{
		UserID:    u.UserID,
		SessionID: sessionID,
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, tc).SignedString([]byte(c.cfg.Token.Secret))
}

func (c *Controller) verifyToken(ctx context.Context, tokenString string) (authInfo *AuthInfo, err error) {
	if ai, ok := c.whiteListTokens[tokenString]; ok {
		return ai, nil
	}

	redisKey, authInfo, err := c.verifyTokenEx(ctx, redisKeyForSession, tokenString)
	if err != nil {
		c.logger.Errorf(ctx, "verify token failed: %v", err)

		return
	}

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Expire(ctx, redisKey, c.cfg.Token.Expire).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "set ttl of key %v failed: %v", redisKey, err)

		err = nil
	}

	return
}

func (c *Controller) verifyTokenEx(ctx context.Context, fnRedisKey func(userId int64, sessionId string) string,
	tokenString string) (redisKey string, authInfo *AuthInfo, err error) {
	var tc TokenClaims

	_, err = jwt.ParseWithClaims(tokenString, &tc, func(token *jwt.Token) (interface{}, error) {
		return []byte(c.cfg.Token.Secret), nil
	})

	if err != nil {
		c.logger.Errorf(ctx, "verifyTokenEx failed: %v", err)

		return
	}

	redisKey = fnRedisKey(tc.UserID, tc.SessionID)

	authInfo, err = c.verifySessionID(ctx, tc.UserID, tc.SessionID, redisKey)
	if err != nil {
		c.logger.Errorf(ctx, "verify session id [%v-%v] failed: %v", tc.UserID, tc.SessionID, err)

		return
	}

	if authInfo.ParentSessionID != "" {
		_, err = c.verifySessionID(ctx, authInfo.UserID, authInfo.ParentSessionID, redisKeyForSession(authInfo.UserID, authInfo.ParentSessionID))

		c.logger.Errorf(ctx, "verify parent session id %v failed: %v", authInfo.ParentSessionID)

		return
	}

	return
}

func (c *Controller) verifySessionID(ctx context.Context, userID int64, sessionID, redisKey string) (authInfo *AuthInfo, err error) {
	var data string

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		data, err = c.redis.Get(ctx, redisKey).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "get session failed: %v, %v", err, redisKey)

		return
	}

	authInfo = &AuthInfo{}

	err = json.Unmarshal([]byte(data), authInfo)
	if err != nil {
		c.logger.Errorf(ctx, "unmarshal user info failed: %v, %v", err, data)

		return
	}

	if authInfo.UserID != userID {
		err = fmt.Errorf("user id miss: %v, %v", authInfo.UserID, userID)
		c.logger.Error(ctx, err)

		return
	}

	if authInfo.SessionID != sessionID {
		err = fmt.Errorf("session id miss: %v, %v", authInfo.SessionID, sessionID)
		c.logger.Error(ctx, err)

		return
	}

	if time.Now().Unix() > authInfo.ExpiresAt {
		err = fmt.Errorf("token timeout: %v, now is %v", time.Unix(authInfo.ExpiresAt, 0), time.Now())
		c.logger.Warnf(ctx, err.Error())

		return
	}

	clientIP := c.utils.GetPeerIP(ctx)
	if !c.compareIP(ctx, authInfo.ClientIP, clientIP) {
		err = fmt.Errorf("ip miss: %v, now is %v", authInfo.ClientIP, clientIP)
		c.logger.Warnf(ctx, err.Error())

		return
	}

	return
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
		c.redis.Del(ctx, redisKeyForSession(tc.UserID, tc.SessionID))
	})

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		children, err := c.redis.SMembers(ctx, redisKeyForSessionIDParent(tc.SessionID)).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				c.logger.Errorf(ctx, "redis smembers %v failed: %v", tc.SessionID, err)
			}

			return
		}
		if len(children) <= 0 {
			return
		}
		for _, sessionID := range children {
			utils.DefRedisTimeoutOp(func(ctx context.Context) {
				err = c.redis.Del(ctx, redisKeyForSession(tc.UserID, sessionID)).Err()
				if err != nil {
					c.logger.Errorf(ctx, "redis del %v failed: %v", redisKeyForSession(tc.UserID, tc.SessionID), err)
				}
			})
		}

		utils.DefRedisTimeoutOp(func(ctx context.Context) {
			c.redis.Del(ctx, redisKeyForSessionIDParent(tc.SessionID))
		})
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

	c.logger.Warnf(ctx, "ip miss: %v, %v", netIP1.String(), netIP2.String())

	return false
}

func (c *Controller) getUserTokenCookie(ctx context.Context) string {
	return grpce.GetStringFromContext(ctx, user.SignCookieName)
}

func (c *Controller) genGaToken(ctx context.Context, userID int64) (token string, err error) {
	token = uuid.NewV4().String()

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, redisKeyForGaToken(userID, token), time.Now().String(), c.cfg.GoogleAuthenticator.TokenExpire).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "set redis key for ga token failed: %v", err)

		return
	}

	return
}

func (c *Controller) gaTokenExists(ctx context.Context, userID int64, token string) bool {
	key := redisKeyForGaToken(userID, token)

	var err error

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Get(ctx, key).Result()
	})

	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.logger.Errorf(ctx, "redis %v err: %v", key, err)
		}

		return false
	}

	return true
}

func (c *Controller) removeGaToken(_ context.Context, userID int64, token string) {
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		c.redis.Del(ctx, redisKeyForGaToken(userID, token))
	})
}

func (c *Controller) genCsrfToken(ctx context.Context, token string) (string, error) {
	tokenSessionID := uuid.NewV4().String()

	key := redisKeyForCsrfToken(tokenSessionID)

	var err error

	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		_, err = c.redis.Set(ctx, key, token, c.cfg.CsrfExpire).Result()
	})

	if err != nil {
		c.logger.Errorf(ctx, "set redis %v failed: %v", key, err)

		return "", err
	}

	return tokenSessionID, err
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

		return userpb.UserStatus_USER_STATUS_WRONG_CODE, err
	}

	_, err = c.verifyToken(ctx, token)
	if err != nil {
		c.logger.Errorf(ctx, "redis invalid token: %v", err)

		return userpb.UserStatus_USER_STATUS_WRONG_CODE, err
	}

	c.removeCsrfToken(ctx, csrfToken)

	return userpb.UserStatus_USER_STATUS_SUCCESS, nil
}

func (c *Controller) removeCsrfToken(_ context.Context, csrfToken string) {
	utils.DefRedisTimeoutOp(func(ctx context.Context) {
		c.redis.Del(ctx, redisKeyForCsrfToken(csrfToken))
	})
}
