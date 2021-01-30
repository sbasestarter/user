package helper

import (
	"context"
	"github.com/jiuzhou-zhao/go-fundamental/iputils"
)

type UtilsImpl struct{}

func NewUtilsImpl() *UtilsImpl {
	return &UtilsImpl{}
}

func (u *UtilsImpl) RandomString(n int, allowedChars ...[]rune) string {
	return randomString(n, allowedChars...)
}

func (u *UtilsImpl) GetPeerIp(ctx context.Context) string {
	return iputils.GrpcGetRealIP(ctx)
}
