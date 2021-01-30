package factory

import (
	"context"
	"time"

	"github.com/jiuzhou-zhao/go-fundamental/discovery"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/helper"
)

type Utils interface {
	RandomString(n int, allowedChars ...[]rune) string
	GetPeerIp(ctx context.Context) string
}

type HttpToken interface {
	SetUserTokenCookie(ctx context.Context, token string) error
	UnsetUserTokenCookie(ctx context.Context, token string) error
}

type Factory interface {
	GetGRPCClientFactory() GRPCClientFactory
	GetUtils() Utils
	GetHttpToken() HttpToken
}

func NewFactory(ctx context.Context, getter discovery.Getter, cfg *config.Config) Factory {
	return &factoryImpl{
		ctx:    ctx,
		getter: getter,
		cfg:    cfg,
	}
}

type factoryImpl struct {
	ctx    context.Context
	getter discovery.Getter
	cfg    *config.Config
}

func (impl *factoryImpl) GetGRPCClientFactory() GRPCClientFactory {
	return NewGRPCClientFactory(impl.ctx, impl.getter, impl.cfg)
}

func (impl *factoryImpl) GetUtils() Utils {
	return helper.NewUtilsImpl()
}

func (impl *factoryImpl) GetHttpToken() HttpToken {
	return NewHttpToken(impl.cfg.Token.Domain, int(impl.cfg.Token.Expire/time.Second))
}
