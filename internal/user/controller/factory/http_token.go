package factory

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/sbasestarter/user/pkg/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type httpTokenImpl struct {
	domain       string
	cookieMaxAge int
}

func NewHttpToken(domain string, cookieMaxAge int) HttpToken {
	return &httpTokenImpl{
		domain:       domain,
		cookieMaxAge: cookieMaxAge,
	}
}

func (impl *httpTokenImpl) SetUserTokenCookie(ctx context.Context, token string) error {
	domain := impl.domainFromContext(ctx)
	domain = strings.Trim(domain, " \r\n\t")
	if domain == "" {
		domain = impl.domain
	}

	cookie := http.Cookie{
		Domain:   domain,
		Name:     user.SignCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   impl.cookieMaxAge}
	return grpc.SendHeader(ctx, metadata.Pairs("Set-Cookie", cookie.String()))
}

func (impl *httpTokenImpl) UnsetUserTokenCookie(ctx context.Context, token string) error {
	domain := impl.domainFromContext(ctx)
	domain = strings.Trim(domain, " \r\n\t")
	if domain == "" {
		domain = impl.domain
	}

	cookie := http.Cookie{
		Domain:   domain,
		Name:     user.SignCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().AddDate(-1, 0, 0)}
	return grpc.SendHeader(ctx, metadata.Pairs("Set-Cookie", cookie.String()))
}

func (impl *httpTokenImpl) domainFromContext(ctx context.Context) string {
	domain := ""
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		values := md.Get("origin")
		if len(values) > 0 {
			domain = values[0]
		}
	}
	idx := strings.Index(domain, "://")
	if idx != -1 {
		domain = domain[idx+3:]
	}
	idx = strings.Index(domain, ":")
	if idx != -1 {
		domain = domain[0:idx]
	}
	return domain
}
