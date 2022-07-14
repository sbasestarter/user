package helper

import (
	"context"

	"github.com/sgostarter/libservicetoolset/grpce"
)

type UtilsImpl struct{}

func NewUtilsImpl() *UtilsImpl {
	return &UtilsImpl{}
}

func (u *UtilsImpl) RandomString(n int, allowedChars ...[]rune) string {
	return randomString(n, allowedChars...)
}

func (u *UtilsImpl) GetPeerIP(ctx context.Context) string {
	return grpce.GrpcGetRealIP(ctx)
}
