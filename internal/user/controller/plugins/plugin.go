package plugins

import (
	"context"

	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
)

type Plugin interface {
	FixUserId(user *userpb.UserId) (*userpb.UserId, bool)
	TriggerAuthentication(ctx context.Context, userName, code string, validDelaySeconds uint32) (err error)
	GetNickName(ctx context.Context, userName string) string
	TryAutoLogin(ctx context.Context, user *userpb.UserId, token string) (
		userFixed *userpb.UserId, nickName, avatar string, err error)
}
