package plugins

import (
	"context"
	"time"

	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

type Plugin interface {
	FixUserId(ctx context.Context, user *userpb.UserId) (*userpb.UserId, bool, error)
	TriggerAuthentication(ctx context.Context, userName, code string, purpose userpb.TriggerAuthPurpose) (err error)
	GetNickName(ctx context.Context, userName string) string
	TryAutoLogin(ctx context.Context, user *userpb.UserId, token string) (
		userFixed *userpb.UserId, nickName, avatar string, err error)
	GetSendLockTimeDuration() time.Duration
	GetValidDelayDuration() time.Duration
}
