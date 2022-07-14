package factory

import (
	"context"
	"time"

	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/helper"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/librediscovery/discovery"
)

type Utils interface {
	RandomString(n int, allowedChars ...[]rune) string
	GetPeerIP(ctx context.Context) string
}

type HTTPToken interface {
	SetUserTokenCookie(ctx context.Context, token string) error
	UnsetUserTokenCookie(ctx context.Context, token string) error
}

type Factory interface {
	GetGRPCClientFactory() GRPCClientFactory
	GetUtils() Utils
	GetHTTPToken() HTTPToken
}

func NewFactory(ctx context.Context, getter discovery.Getter, cfg *config.Config, logger l.Wrapper) Factory {
	return &factoryImpl{
		ctx:    ctx,
		getter: getter,
		cfg:    cfg,
		logger: logger,
	}
}

type factoryImpl struct {
	ctx    context.Context
	getter discovery.Getter
	cfg    *config.Config
	logger l.Wrapper
}

func (impl *factoryImpl) GetGRPCClientFactory() GRPCClientFactory {
	return NewGRPCClientFactory(impl.ctx, impl.getter, impl.cfg, impl.logger)
}

func (impl *factoryImpl) GetUtils() Utils {
	return helper.NewUtilsImpl()
}

func (impl *factoryImpl) GetHTTPToken() HTTPToken {
	return NewHTTPToken(impl.cfg.Token.Domain, int(impl.cfg.Token.Expire/time.Second))
}
