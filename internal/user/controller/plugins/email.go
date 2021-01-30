package plugins

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/caixw/lib.go/validation/validator"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/sbasestarter/proto-repo/gen/protorepo-post-go"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/user/controller/factory"
)

type EmailAuthentication struct {
	postClient postpb.PostServiceClient
}

func NewEmailAuthentication(cliFactory factory.GRPCClientFactory) *EmailAuthentication {
	return &EmailAuthentication{
		postClient: cliFactory.GetPostCenterClient(),
	}
}

func (ea *EmailAuthentication) FixUserId(user *userpb.UserId) (*userpb.UserId, bool) {
	switch user.UserVe {
	case userpb.VerificationEquipment_VEMail.String():
		return user, true
	case userpb.VerificationEquipment_VEAuto.String():
		if validator.IsEmail(user.UserName) {
			user.UserVe = userpb.VerificationEquipment_VEMail.String()
			return user, true
		}
		return nil, false
	}
	return nil, false
}

func (ea *EmailAuthentication) TriggerAuthentication(ctx context.Context, userName, code string, validDelay time.Duration) (err error) {
	err = ea.sendEmail(ctx, "验证码", "0", userName, code, validDelay)
	if err != nil {
		return
	}
	return
}

func (ea *EmailAuthentication) sendEmail(ctx context.Context, title, templateId, email, code string, expiredDuration time.Duration) error {
	ctx, closer := context.WithTimeout(ctx, 1*time.Minute)
	defer closer()

	req := &postpb.SendTemplateRequest{
		ProtocolType: "email",
		To:           []string{email},
		TemplateId:   templateId,
		Vars: []string{
			title,
			fmt.Sprintf("您的验证码为 %v, 过期时间为 %v", code, time.Now().Add(expiredDuration)),
			"羊米测试",
		},
		XXX_NoUnkeyedLiteral: struct{}{},
		XXX_unrecognized:     nil,
		XXX_sizecache:        0,
	}

	resp, err := ea.postClient.SendTemplate(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status.GetStatus() != postpb.PostStatus_PS_SUCCESS {
		err = fmt.Errorf("%v:%v", resp.Status.GetStatus(), resp.Status.Msg)
		return err
	}
	return nil
}

// 大于等于4位，显示前2后1。小于等于3位，隐藏末位
func (ea *EmailAuthentication) makeMaskSafeMail(ctx context.Context, mail string) string {
	mailParts := strings.Split(mail, "@")
	if len(mailParts) != 2 {
		loge.Errorf(ctx, "invalid mail: %v", mail)
		return ""
	}
	if len(mailParts[0]) <= 0 {
		loge.Errorf(ctx, "invalid mail: %v", mail)
		return ""
	}
	if len(mailParts[0]) >= 4 {
		mailParts[0] = mailParts[0][0:2] + "***" + mailParts[0][len(mailParts[0])-1:]
	} else {
		mailParts[0] = mailParts[0][0:len(mailParts[0])-1] + "***"
	}
	return fmt.Sprintf("%v@%v", mailParts[0], mailParts[1])
}

func (ea *EmailAuthentication) GetNickName(ctx context.Context, userName string) string {
	return ea.makeMaskSafeMail(ctx, userName)
}
