package config

import (
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-xorm/xorm"
	"github.com/sgostarter/libconfig"
	"github.com/sgostarter/libeasygo/stg"
	"github.com/sgostarter/libservicetoolset/clienttoolset"
	"github.com/sgostarter/libservicetoolset/servicetoolset"
)

type Config struct {
	GRpcServerConfig          servicetoolset.GRPCServerConfig `yaml:"grpc_server_config" json:"grpc_server_config"`
	GRpcClientConfigTpl       clienttoolset.GRPCClientConfig  `yaml:"grpc_client_config_tpl" json:"grpc_client_config_tpl"`
	GoogleAuthenticator       googleAuthenticatorOption       `json:"google_authenticator" json:"google_authenticator"`
	DefaultUserAvatar         string                          `yaml:"default_user_avatar" json:"default_user_avatar"`
	PwdSecret                 string                          `yaml:"pwd_secret" json:"pwd_secret"`
	Token                     tokenConfig                     `yaml:"token" json:"token"`
	DummyVerifyCode           string                          `yaml:"dummy_verify_code" json:"dummy_verify_code"`
	EmailConfig               VEConfig                        `yaml:"email_config" json:"email_config"`
	PhoneConfig               VEConfig                        `yaml:"phone_config" json:"phone_config"`
	CsrfExpire                time.Duration                   `yaml:"csrf_expire" json:"csrf_expire"`
	WhiteListTokens           []string                        `yaml:"white_list_tokens" json:"white_list_tokens"`
	WhiteListSSOJumpDomain    []string                        `yaml:"white_list_sso_jump_domain" json:"white_list_sso_jump_domain"`
	WhiteListSSOJumpDomainMap map[string]interface{}          `yaml:"-" ignored:"true"`

	DiscoveryServerNames map[string]string `yaml:"discovery_server_names" json:"discovery_server_names"`

	RedisDSN string        `yaml:"redis_dsn" json:"redis_dsn"`
	RedisCli *redis.Client `yaml:"-" json:"-" ignored:"true"`
	MySqlDSN string        `yaml:"my_sql_dsn" json:"my_sql_dsn"`
	MySqlCli *xorm.Engine  `yaml:"-" json:"-" ignored:"true"`
}

type VEConfig struct {
	SendDelayDuration  time.Duration `yaml:"send_delay_duration"`
	ValidDelayDuration time.Duration `yaml:"valid_delay_duration"`
}

type UserAuthentication struct {
	SupportFixUserId bool          `yaml:"support_fix_user_id"`
	SupportAutoLogin bool          `yaml:"support_auto_login"`
	CodeValid        time.Duration `yaml:"code_valid"`
	SendLock         time.Duration `yaml:"send_lock"`
}

type tokenConfig struct {
	Secret    string        `yaml:"secret"`
	Domain    string        `yaml:"domain"`
	Expire    time.Duration `yaml:"expire"`
	SSOExpire time.Duration `yaml:"sso_expire"`
}

type googleAuthenticatorOption struct {
	Force       bool          `yaml:"force"`
	Enable      bool          `yaml:"enable"`
	Issuer      string        `yaml:"issuer"`
	KeyExpire   time.Duration `yaml:"key_expire"`
	TokenExpire time.Duration `yaml:"token_expire"`
}

func (cfg *Config) fixConfig() {
	if cfg.GRpcServerConfig.TLSConfig != nil {
		if len(cfg.GRpcServerConfig.TLSConfig.Key) == 0 {
			cfg.GRpcServerConfig.TLSConfig = nil
		}
	}
	if cfg.GRpcClientConfigTpl.TLSConfig != nil {
		if len(cfg.GRpcClientConfigTpl.TLSConfig.Key) == 0 {
			cfg.GRpcClientConfigTpl.TLSConfig = nil
		}
	}
	if cfg.EmailConfig.SendDelayDuration <= 0 {
		cfg.EmailConfig.SendDelayDuration = time.Second
	}
	if cfg.EmailConfig.ValidDelayDuration <= 0 {
		cfg.EmailConfig.ValidDelayDuration = time.Minute
	}
	if cfg.PhoneConfig.SendDelayDuration <= 0 {
		cfg.PhoneConfig.SendDelayDuration = time.Second
	}
	if cfg.PhoneConfig.ValidDelayDuration <= 0 {
		cfg.PhoneConfig.ValidDelayDuration = time.Minute
	}
	cfg.WhiteListSSOJumpDomainMap = make(map[string]interface{})
	for _, s := range cfg.WhiteListSSOJumpDomain {
		cfg.WhiteListSSOJumpDomainMap[s] = true
	}
	if cfg.GoogleAuthenticator.KeyExpire <= 0 {
		cfg.GoogleAuthenticator.KeyExpire = time.Minute
	}
	if cfg.GoogleAuthenticator.TokenExpire <= 0 {
		cfg.GoogleAuthenticator.TokenExpire = 5 * time.Minute
	}
}

func (cfg *Config) init() {
	cfg.fixConfig()

	redisCli, err := stg.InitRedis(cfg.RedisDSN)
	if err != nil {
		panic(err)
	}

	cfg.RedisCli = redisCli

	mysqlCli, err := xorm.NewEngine("mysql", cfg.MySqlDSN)
	if err != nil {
		panic(err)
	}

	cfg.MySqlCli = mysqlCli
}

var (
	_config Config
	_once   sync.Once
)

func Get() *Config {
	_once.Do(func() {
		_, err := libconfig.Load("config.yaml", &_config)
		if err != nil {
			panic(err)
		}
		_config.init()
	})

	return &_config
}
