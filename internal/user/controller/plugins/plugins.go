package plugins

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
)

type Plugins struct {
	cfg                 *config.Config
	emailAuthentication *EmailAuthentication
}

func NewPlugins(cfg *config.Config, cliFactory factory.GRPCClientFactory) *Plugins {
	return &Plugins{
		cfg:                 cfg,
		emailAuthentication: NewEmailAuthentication(cliFactory),
	}
}

func (ps *Plugins) FixUserId(ctx context.Context, user *userpb.UserId) (status userpb.UserStatus,
	userFixed *userpb.UserId) {
	if user == nil {
		status = userpb.UserStatus_US_FAILED
		loge.Errorf(ctx, "invalid user: %+v", user)
		return
	}

	veFixed := false
	if v, err := strconv.Atoi(user.UserVe); err == nil {
		if vs, ok := userpb.VerificationEquipment_name[int32(v)]; ok {
			user.UserVe = vs
			veFixed = true
		}
	}

	userResp, ok := ps.emailAuthentication.FixUserId(user)
	if ok {
		status = userpb.UserStatus_US_SUCCESS
		userFixed = userResp
		return
	}

	if veFixed {
		userFixed = user
		return
	}

	// TODO add other ve

	status = userpb.UserStatus_US_DONT_SUPPORT
	return
}

func (ps *Plugins) TriggerAuthentication(ctx context.Context, user *userpb.UserId) (
	status userpb.UserStatus, code string, err error) {
	newCode := ps.newVerifyCode()
	if user.UserVe == userpb.VerificationEquipment_VEMail.String() {
		err = ps.emailAuthentication.TriggerAuthentication(ctx, user.UserName, newCode,
			ps.cfg.EmailConfig.ValidDelayDuration)
		if err != nil {
			status = userpb.UserStatus_US_FAILED
		} else {
			status = userpb.UserStatus_US_SUCCESS
			code = newCode
		}
		return
	}
	status = userpb.UserStatus_US_DONT_SUPPORT
	return
}

func (ps *Plugins) GetNickName(ctx context.Context, user *userpb.UserId) (status userpb.UserStatus, nickName string) {
	if user == nil {
		status = userpb.UserStatus_US_FAILED
		return
	}
	if user.UserVe == userpb.VerificationEquipment_VEMail.String() {
		nickName = ps.emailAuthentication.GetNickName(ctx, user.UserName)
		status = userpb.UserStatus_US_SUCCESS
		return
	}
	status = userpb.UserStatus_US_DONT_SUPPORT
	return
}

func (ps *Plugins) TryAutoLogin(ctx context.Context, user *userpb.UserId, token string) (
	status userpb.UserStatus, userFixed *userpb.UserId, nickName, avatar string) {
	if user.UserVe == userpb.VerificationEquipment_VEWxMinA.String() {
		loge.Warn(ctx, "WxMinA not implement")
		status = userpb.UserStatus_US_NOT_IMPLEMENT
		return
	}
	status = userpb.UserStatus_US_DONT_SUPPORT
	return
}

func (ps *Plugins) SendLockTimeDuration(_ context.Context, user *userpb.UserId) time.Duration {
	switch user.UserVe {
	case userpb.VerificationEquipment_VEMail.String():
		return ps.cfg.EmailConfig.SendDelayDuration
	}
	return 0
}

func (ps *Plugins) ValidDelayDuration(ctx context.Context, user *userpb.UserId) time.Duration {
	switch user.UserVe {
	case userpb.VerificationEquipment_VEMail.String():
		return ps.cfg.EmailConfig.ValidDelayDuration
	}
	return 10 * time.Minute
}

func (ps *Plugins) newVerifyCode() string {
	if ps.cfg.DummyVerifyCode != "" {
		return ps.cfg.DummyVerifyCode
	}
	return fmt.Sprintf("%v", rand.Intn(900000)+100000)
}
