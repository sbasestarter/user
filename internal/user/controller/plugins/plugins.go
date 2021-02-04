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
	cfg             *config.Config
	authentications map[string]Plugin
}

func NewPlugins(cfg *config.Config, cliFactory factory.GRPCClientFactory) *Plugins {
	plugins := &Plugins{
		cfg:             cfg,
		authentications: make(map[string]Plugin),
	}

	plugins.authentications[userpb.VerificationEquipment_VEMail.String()] =
		NewEmailAuthentication(&cfg.EmailConfig, cliFactory)
	plugins.authentications[userpb.VerificationEquipment_VEPhone.String()] =
		NewPhoneAuthentication(&cfg.PhoneConfig, cliFactory)

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

func (ps *Plugins) FixUserId(ctx context.Context, user *userpb.UserId) (status userpb.UserStatus,
	userFixed *userpb.UserId, err error) {

	status = userpb.UserStatus_US_DONT_SUPPORT

	if user == nil {
		status = userpb.UserStatus_US_FAILED
		err = fmt.Errorf("invalid user: %+v", user)
		loge.Error(ctx, err)
		return
	}

	if v, err := strconv.Atoi(user.UserVe); err == nil {
		if vs, ok := userpb.VerificationEquipment_name[int32(v)]; ok {
			user.UserVe = vs
			userFixed = user
		}
	}

	ps.pluginsDo(user, func(plugin Plugin) bool {
		userResp, ok, errRet := plugin.FixUserId(ctx, user)
		if !ok {
			return false
		}
		if errRet != nil {
			err = errRet
			status = userpb.UserStatus_US_BAD_INPUT
		} else {
			status = userpb.UserStatus_US_SUCCESS
			userFixed = userResp
		}
		return true
	})

	return
}

func (ps *Plugins) TriggerAuthentication(ctx context.Context, user *userpb.UserId, purpose userpb.TriggerAuthPurpose) (
	status userpb.UserStatus, code string, err error) {

	status = userpb.UserStatus_US_DONT_SUPPORT

	newCode := ps.newVerifyCode()

	ps.pluginDo(user, func(plugin Plugin) {
		err = plugin.TriggerAuthentication(ctx, user.UserName, newCode, purpose)
		if err != nil {
			status = userpb.UserStatus_US_FAILED
		} else {
			status = userpb.UserStatus_US_SUCCESS
			code = newCode
		}
	})
	return
}

func (ps *Plugins) GetNickName(ctx context.Context, user *userpb.UserId) (status userpb.UserStatus, nickName string) {
	if user == nil {
		status = userpb.UserStatus_US_FAILED
		return
	}

	status = userpb.UserStatus_US_DONT_SUPPORT

	ps.pluginDo(user, func(plugin Plugin) {
		nickName = plugin.GetNickName(ctx, user.UserName)
		status = userpb.UserStatus_US_SUCCESS
	})

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
	return fmt.Sprintf("%v", rand.Intn(900000)+100000)
}
