package plugins

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caixw/lib.go/validation/validator"
	"github.com/sbasestarter/proto-repo/gen/protorepo-post-sbs-go"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sgostarter/i/l"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type emailAuthentication struct {
	cfg        *config.VEConfig
	postClient postsbspb.PostSBSServiceClient
	logger     l.WrapperWithContext
}

func NewEmailAuthentication(cfg *config.VEConfig, cliFactory factory.GRPCClientFactory, logger l.Wrapper) Plugin {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	return &emailAuthentication{
		cfg:        cfg,
		postClient: cliFactory.GetPostCenterClient(),
		logger:     logger.WithFields(l.StringField(l.ClsKey, "emailAuthentication")).GetWrapperWithContext(),
	}
}

func (ea *emailAuthentication) FixUserId(ctx context.Context, user *userpb.UserId) (*userpb.UserId, bool, error) {
	switch user.UserVe {
	case userpb.VerificationEquipment_VEMail.String():
		if !validator.IsEmail(user.UserName) {
			ea.logger.Errorf(ctx, "unknown email format: %v", user.UserName)
			return nil, true, errors.New("invalid email format")
		}
		return user, true, nil
	case userpb.VerificationEquipment_VEAuto.String():
		if validator.IsEmail(user.UserName) {
			user.UserVe = userpb.VerificationEquipment_VEMail.String()
			return user, true, nil
		}
		return nil, false, nil
	}
	return nil, false, nil
}

func (ea *emailAuthentication) TriggerAuthentication(ctx context.Context, userName, code string, purpose userpb.TriggerAuthPurpose) (err error) {
	err = ea.sendEmail(ctx, purpose, userName, code)
	if err != nil {
		return
	}
	return
}

func (ea *emailAuthentication) sendEmail(ctx context.Context, purpose userpb.TriggerAuthPurpose, userName, code string) error {
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
		err := fmt.Errorf("unknown purpose %v", purposeType)
		ea.logger.Error(ctx, err)
		return err
	}

	req := &postsbspb.PostCodeRequest{
		ProtocolType:     postsbspb.PostProtocolType_PostProtocolMail,
		PurposeType:      purposeType,
		To:               userName,
		Code:             code,
		ExpiredTimestamp: time.Now().Add(ea.cfg.ValidDelayDuration).Unix(),
	}

	resp, err := ea.postClient.PostCode(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status.GetStatus() != postsbspb.PostSBSStatus_PS_SBS_SUCCESS {
		err = fmt.Errorf("%v:%v", resp.Status.GetStatus(), resp.Status.Msg)
		return err
	}
	return nil
}

// 大于等于4位，显示前2后1。小于等于3位，隐藏末位
func (ea *emailAuthentication) makeMaskSafeMail(ctx context.Context, mail string) string {
	mailParts := strings.Split(mail, "@")
	if len(mailParts) != 2 {
		ea.logger.Errorf(ctx, "invalid mail: %v", mail)
		return ""
	}
	if len(mailParts[0]) <= 0 {
		ea.logger.Errorf(ctx, "invalid mail: %v", mail)
		return ""
	}
	if len(mailParts[0]) >= 4 {
		mailParts[0] = mailParts[0][0:2] + "***" + mailParts[0][len(mailParts[0])-1:]
	} else {
		mailParts[0] = mailParts[0][0:len(mailParts[0])-1] + "***"
	}
	return fmt.Sprintf("%v@%v", mailParts[0], mailParts[1])
}

func (ea *emailAuthentication) GetNickName(ctx context.Context, userName string) string {
	return ea.makeMaskSafeMail(ctx, userName)
}

func (ea *emailAuthentication) TryAutoLogin(ctx context.Context, user *userpb.UserId, token string) (
	userFixed *userpb.UserId, nickName, avatar string, err error) {
	err = status.Error(codes.Unimplemented, "")
	return
}

func (ea *emailAuthentication) GetSendLockTimeDuration() time.Duration {
	return ea.cfg.SendDelayDuration
}

func (ea *emailAuthentication) GetValidDelayDuration() time.Duration {
	return ea.cfg.ValidDelayDuration
}
