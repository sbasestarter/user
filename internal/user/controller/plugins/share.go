package plugins

import (
	"context"
	"fmt"
	"time"

	postsbspb "github.com/sbasestarter/proto-repo/gen/protorepo-post-sbs-go"
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

	purposeType := postsbspb.PostPurposeType_PostPurposeNone

	switch purpose {
	case userpb.TriggerAuthPurpose_TriggerAuthPurposeRegister:
		purposeType = postsbspb.PostPurposeType_PostPurposeRegister
	case userpb.TriggerAuthPurpose_TriggerAuthPurposeLogin:
		purposeType = postsbspb.PostPurposeType_PostPurposeLogin
	case userpb.TriggerAuthPurpose_TriggerAuthPurposeResetPassword:
		purposeType = postsbspb.PostPurposeType_PostPurposeResetPassword
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

	resp, err := postClient.PostCode(ctx, req)
	if err != nil {
		return err
	}

	if resp.Status.GetStatus() != postsbspb.PostSBSStatus_PS_SBS_SUCCESS {
		err = cuserror.NewWithErrorMsg(fmt.Sprintf("%v:%v", resp.Status.GetStatus(), resp.Status.Msg))

		return err
	}

	return nil
}
