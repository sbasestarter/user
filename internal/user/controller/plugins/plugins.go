package plugins

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/libeasygo/cuserror"
)

type Plugins struct {
	cfg             *config.Config
	authentications map[string]Plugin
	logger          l.WrapperWithContext
}

func NewPlugins(cfg *config.Config, cliFactory factory.GRPCClientFactory, logger l.Wrapper) *Plugins {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	plugins := &Plugins{
		cfg:             cfg,
		authentications: make(map[string]Plugin),
		logger:          logger.WithFields(l.StringField(l.ClsKey, "Plugins")).GetWrapperWithContext(),
	}

	plugins.authentications[userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_MAIL.String()] =
		NewEmailAuthentication(&cfg.EmailConfig, cliFactory, logger)
	plugins.authentications[userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_PHONE.String()] =
		NewPhoneAuthentication(&cfg.PhoneConfig, cliFactory, logger)

	return plugins
}

func (ps *Plugins) pluginDo(user *userpb.UserId, fn func(plugin Plugin)) {
	if plugin, ok := ps.authentications[user.UserVe]; ok {
		fn(plugin)
	}
}

func (ps *Plugins) pluginsDo(user *userpb.UserId, fn func(plugin Plugin) bool) {
	if plugin, ok := ps.authentications[user.UserVe]; ok {
		fn(plugin)

		return
	}

	for _, plugin := range ps.authentications {
		result := fn(plugin)
		if result {
			break
		}
	}
}

func (ps *Plugins) FixUserID(ctx context.Context, user *userpb.UserId) (status userpb.UserStatus,
	userFixed *userpb.UserId, err error) {
	status = userpb.UserStatus_USER_STATUS_DONT_SUPPORT

	if user == nil {
		status = userpb.UserStatus_USER_STATUS_FAILED

		err = cuserror.NewWithErrorMsg(fmt.Sprintf("invalid user: %+v", user))

		ps.logger.Error(ctx, err)

		return
	}

	// nolint: gosec
	if v, errE := strconv.Atoi(user.UserVe); errE == nil {
		if vs, ok := userpb.VerificationEquipment_name[int32(v)]; ok {
			user.UserVe = vs
			userFixed = user
		}
	}

	ps.pluginsDo(user, func(plugin Plugin) bool {
		userResp, ok, errRet := plugin.FixUserID(ctx, user)
		if !ok {
			return false
		}

		if errRet != nil {
			err = errRet
			status = userpb.UserStatus_USER_STATUS_BAD_INPUT
		} else {
			status = userpb.UserStatus_USER_STATUS_SUCCESS
			userFixed = userResp
		}

		return true
	})

	return
}

func (ps *Plugins) TriggerAuthentication(ctx context.Context, user *userpb.UserId, purpose userpb.TriggerAuthPurpose) (
	status userpb.UserStatus, code string, err error) {
	status = userpb.UserStatus_USER_STATUS_DONT_SUPPORT

	newCode := ps.newVerifyCode()

	ps.pluginDo(user, func(plugin Plugin) {
		err = plugin.TriggerAuthentication(ctx, user.UserName, newCode, purpose)
		if err != nil {
			status = userpb.UserStatus_USER_STATUS_FAILED
		} else {
			status = userpb.UserStatus_USER_STATUS_SUCCESS
			code = newCode
		}
	})

	return
}

func (ps *Plugins) GetNickName(ctx context.Context, user *userpb.UserId) (status userpb.UserStatus, nickName string) {
	if user == nil {
		status = userpb.UserStatus_USER_STATUS_FAILED

		return
	}

	status = userpb.UserStatus_USER_STATUS_DONT_SUPPORT

	ps.pluginDo(user, func(plugin Plugin) {
		nickName = plugin.GetNickName(ctx, user.UserName)
		status = userpb.UserStatus_USER_STATUS_SUCCESS
	})

	return
}

func (ps *Plugins) TryAutoLogin(ctx context.Context, user *userpb.UserId, token string) (
	status userpb.UserStatus, userFixed *userpb.UserId, nickName, avatar string) {
	if user.UserVe == userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_WX_MINA.String() {
		ps.logger.Warn(ctx, "WxMinA not implement")

		status = userpb.UserStatus_USER_STATUS_NOT_IMPLEMENT

		return
	}

	status = userpb.UserStatus_USER_STATUS_DONT_SUPPORT

	return
}

func (ps *Plugins) SendLockTimeDuration(_ context.Context, user *userpb.UserId) (duration time.Duration) {
	ps.pluginDo(user, func(plugin Plugin) {
		duration = plugin.GetSendLockTimeDuration()
	})

	return
}

func (ps *Plugins) ValidDelayDuration(ctx context.Context, user *userpb.UserId) (duration time.Duration) {
	ps.pluginDo(user, func(plugin Plugin) {
		duration = plugin.GetValidDelayDuration()
	})

	return
}

func (ps *Plugins) newVerifyCode() string {
	if ps.cfg.DummyVerifyCode != "" {
		return ps.cfg.DummyVerifyCode
	}

	// nolint: gosec
	return fmt.Sprintf("%v", rand.Intn(900000)+100000)
}
