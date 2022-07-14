package plugins

import (
	"context"
	"fmt"
	"strings"
	"time"

	postsbspb "github.com/sbasestarter/proto-repo/gen/protorepo-postsbs-go"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/libeasygo/cuserror"
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

func (pa *phoneAuthentication) FixUserID(ctx context.Context, user *userpb.UserId) (*userpb.UserId, bool, error) {
	switch user.UserVe {
	case userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_PHONE.String():
		userName, err := pa.fixPhone(ctx, user.UserName)
		if err != nil {
			return nil, true, err
		}

		user.UserName = userName

		return user, true, nil
	case userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_UNSPECIFIED.String():
		userName, err := pa.fixPhone(ctx, user.UserName)
		if err == nil {
			user.UserName = userName
			user.UserVe = userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_PHONE.String()

			return user, true, nil
		}

		return nil, false, nil
	}

	return nil, false, nil
}

func (pa *phoneAuthentication) TriggerAuthentication(ctx context.Context, userName, code string,
	purpose userpb.TriggerAuthPurpose) (err error) {
	return GRPCPostCode(ctx, purpose, userName, code, pa.cfg, pa.postClient,
		postsbspb.PostProtocolType_POST_PROTOCOL_TYPE_SMS, pa.logger)
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

		err = cuserror.NewWithErrorMsg(fmt.Sprintf("phone type: %v", phoneType))

		pa.logger.Infof(ctx, err.Error())

		return "", err
	}

	return libphonenumber.Format(num, libphonenumber.E164), nil
}
