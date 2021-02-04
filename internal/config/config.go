package config

import (
	"time"

	"github.com/jiuzhou-zhao/go-fundamental/dbtoolset"
	"github.com/jiuzhou-zhao/go-fundamental/servicetoolset"
)

type Config struct {
	GRpcServerConfig    servicetoolset.GRpcServerConfig
	DBConfig            dbtoolset.DBConfig
	GoogleAuthenticator googleAuthenticatorOption
	DefaultUserAvatar   string
	PwdSecret           string
	Token               tokenConfig
	DummyVerifyCode     string
	EmailConfig         VEConfig
	PhoneConfig         VEConfig
	CsrfExpire          time.Duration
	WhiteListTokens     []string

	DiscoveryServerNames map[string]string
}

type VEConfig struct {
	SendDelayDuration  time.Duration
	ValidDelayDuration time.Duration
}

type UserAuthentication struct {
	// clienttoolset.GRpcClientConfig `yaml:",inline"`
	SupportFixUserId bool
	SupportAutoLogin bool
	CodeValid        time.Duration
	SendLock         time.Duration
}

type tokenConfig struct {
	Secret    string
	Domain    string
	Expire    time.Duration
	SSOExpire time.Duration
}

type googleAuthenticatorOption struct {
	Force       bool
	Enable      bool
	Issuer      string
	KeyExpire   time.Duration
	TokenExpire time.Duration
}
