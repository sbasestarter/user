package plugins

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sbasestarter/proto-repo/gen/protorepo-post-sbs-go"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sgostarter/i/l"
	"github.com/ttacon/libphonenumber"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type phoneAuthentication struct {
	cfg        *config.VEConfig
	postClient postsbspb.PostSBSServiceClient
	logger     l.WrapperWithContext
}

func NewPhoneAuthentication(cfg *config.VEConfig, cliFactory factory.GRPCClientFactory, logger l.Wrapper) Plugin {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	return &phoneAuthentication{
		cfg:        cfg,
		postClient: cliFactory.GetPostCenterClient(),
		logger:     logger.WithFields(l.StringField(l.ClsKey, "phoneAuthentication")).GetWrapperWithContext(),
	}
}

func (pa *phoneAuthentication) FixUserId(ctx context.Context, user *userpb.UserId) (*userpb.UserId, bool, error) {
	switch user.UserVe {
	case userpb.VerificationEquipment_VEPhone.String():
		userName, err := pa.fixPhone(ctx, user.UserName)
		if err != nil {
			return nil, true, err
		}
		user.UserName = userName
		return user, true, nil
	case userpb.VerificationEquipment_VEAuto.String():
		userName, err := pa.fixPhone(ctx, user.UserName)
		if err == nil {
			user.UserName = userName
			user.UserVe = userpb.VerificationEquipment_VEPhone.String()
			return user, true, nil
		}
		return nil, false, nil
	}
	return nil, false, nil
}

func (pa *phoneAuthentication) TriggerAuthentication(ctx context.Context, userName, code string,
	purpose userpb.TriggerAuthPurpose) (err error) {
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
		pa.logger.Error(ctx, err)
		return err
	}

	req := &postsbspb.PostCodeRequest{
		ProtocolType:     postsbspb.PostProtocolType_PostProtocolSMS,
		PurposeType:      purposeType,
		To:               userName,
		Code:             code,
		ExpiredTimestamp: time.Now().Add(pa.cfg.ValidDelayDuration).Unix(),
	}
	resp, err := pa.postClient.PostCode(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status.GetStatus() != postsbspb.PostSBSStatus_PS_SBS_SUCCESS {
		err = fmt.Errorf("%v:%v", resp.Status.GetStatus(), resp.Status.Msg)
		return err
	}
	return nil
}

func (pa *phoneAuthentication) GetNickName(ctx context.Context, userName string) string {
	return pa.makeMaskPhone(userName)
}

func (pa *phoneAuthentication) makeMaskPhone(phone string) string {
	return fmt.Sprintf("%v****%v", phone[:(len(phone)-8)], phone[len(phone)-4:])
}

func (pa *phoneAuthentication) TryAutoLogin(ctx context.Context, user *userpb.UserId, token string) (
	userFixed *userpb.UserId, nickName, avatar string, err error) {
	err = status.Error(codes.Unimplemented, "")
	return
}

func (pa *phoneAuthentication) GetSendLockTimeDuration() time.Duration {
	return pa.cfg.SendDelayDuration
}

func (pa *phoneAuthentication) GetValidDelayDuration() time.Duration {
	return pa.cfg.ValidDelayDuration
}

func (pa *phoneAuthentication) fixPhone(ctx context.Context, phone string) (string, error) {
	if !strings.HasPrefix(phone, "+") {
		phone = "+86" + phone
	}
	num, err := libphonenumber.Parse(phone, "")
	if err != nil {
		pa.logger.Errorf(ctx, "fixPhoneWithContext %v failed: %v", phone, err)
		return "", err
	}

	res := libphonenumber.IsPossibleNumberWithReason(num)
	if res != libphonenumber.IS_POSSIBLE {
		pa.logger.Errorf(ctx, "phone number impossible: %#v len:%v %v", phone, len(phone), res)
	}

	region := libphonenumber.GetRegionCodeForNumber(num)

	valid := libphonenumber.IsValidNumberForRegion(num, region)

	if !valid {
		phoneType := libphonenumber.GetNumberType(num)
		err = fmt.Errorf("phone type: %v", phoneType)
		pa.logger.Infof(ctx, err.Error())
		return "", err
	}

	return libphonenumber.Format(num, libphonenumber.E164), nil
}
