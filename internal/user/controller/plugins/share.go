package plugins

import (
	"context"
	"fmt"
	"time"

	postsbspb "github.com/sbasestarter/proto-repo/gen/protorepo-postsbs-go"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/libeasygo/cuserror"
)

func GRPCPostCode(ctx context.Context, purpose userpb.TriggerAuthPurpose, userName, code string,
	cfg *config.VEConfig, postClient postsbspb.PostSBSServiceClient, protocolType postsbspb.PostProtocolType,
	logger l.WrapperWithContext) error {
	if logger == nil {
		logger = l.NewNopLoggerWrapper().GetWrapperWithContext()
	}

	ctx, closer := context.WithTimeout(ctx, 1*time.Minute)
	defer closer()

	purposeType := postsbspb.PostPurposeType_POST_PURPOSE_TYPE_UNSPECIFIED

	switch purpose {
	case userpb.TriggerAuthPurpose_TRIGGER_AUTH_PURPOSE_REGISTER:
		purposeType = postsbspb.PostPurposeType_POST_PURPOSE_TYPE_REGISTER
	case userpb.TriggerAuthPurpose_TRIGGER_AUTH_PURPOSE_LOGIN:
		purposeType = postsbspb.PostPurposeType_POST_PURPOSE_TYPE_LOGIN
	case userpb.TriggerAuthPurpose_TRIGGER_AUTH_PURPOSE_RESET_PASSWORD:
		purposeType = postsbspb.PostPurposeType_POST_PURPOSE_TYPE_RESET_PASSWORD
	default:
		err := cuserror.NewWithErrorMsg(fmt.Sprintf("unknown purpose %v", purposeType))
		logger.Error(ctx, err)

		return err
	}

	req := &postsbspb.PostCodeRequest{
		ProtocolType:     protocolType,
		PurposeType:      purposeType,
		To:               userName,
		Code:             code,
		ExpiredTimestamp: time.Now().Add(cfg.ValidDelayDuration).Unix(),
	}

	_, err := postClient.PostCode(ctx, req)
	if err != nil {
		return err
	}

	return nil
}
