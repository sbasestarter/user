package utils

import (
	"context"
	"time"

	"github.com/sgostarter/libeasygo/helper"
)

func DefRedisTimeoutOp(cb func(ctx context.Context)) {
	helper.DoWithTimeout(context.Background(), time.Second*5, cb)
}
