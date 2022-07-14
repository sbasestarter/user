package plugins

import (
	"context"
	"reflect"
	"testing"

	postsbspb "github.com/sbasestarter/proto-repo/gen/protorepo-postsbs-go"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sgostarter/i/l"
)

// nolint
func TestEmailAuthentication_FixUserId(t *testing.T) {
	type fields struct {
		postClient postsbspb.PostSBSServiceClient
	}
	type args struct {
		user *userpb.UserId
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *userpb.UserId
		want1  bool
	}{
		{
			"test",
			fields{postClient: nil},
			args{user: &userpb.UserId{
				UserName: "abc@web.com",
				UserVe:   userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_UNSPECIFIED.String(),
			}},
			&userpb.UserId{
				UserName: "abc@web.com",
				UserVe:   userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_MAIL.String(),
			},
			true,
		},
		{
			"test",
			fields{postClient: nil},
			args{user: &userpb.UserId{
				UserName: "abc@web.com",
				UserVe:   userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_MAIL.String(),
			}},
			&userpb.UserId{
				UserName: "abc@web.com",
				UserVe:   userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_MAIL.String(),
			},
			true,
		},
		{
			"test",
			fields{postClient: nil},
			args{user: &userpb.UserId{
				UserName: "a111@aa.cn",
				UserVe:   userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_MAIL.String(),
			}},
			&userpb.UserId{
				UserName: "a111@aa.cn",
				UserVe:   userpb.VerificationEquipment_VERIFICATION_EQUIPMENT_MAIL.String(),
			},
			true,
		},
		{
			"test",
			fields{postClient: nil},
			args{user: &userpb.UserId{
				UserName: "",
				UserVe:   "",
			}},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := &emailAuthentication{
				postClient: tt.fields.postClient,
				logger:     l.NewNopLoggerWrapper().GetWrapperWithContext(),
			}
			got, got1, _ := ea.FixUserID(context.Background(), tt.args.user)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FixUserID() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("FixUserID() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

// nolint
func TestEmailAuthentication_makeMaskSafeMail(t *testing.T) {
	type fields struct {
		postClient postsbspb.PostSBSServiceClient
	}
	type args struct {
		mail string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			"test",
			fields{postClient: nil},
			args{"abcdef@abcd.com"},
			"ab***f@abcd.com",
		},
		{
			"test",
			fields{postClient: nil},
			args{"abcd@abcd.com"},
			"ab***d@abcd.com",
		},
		{
			"test",
			fields{postClient: nil},
			args{"abc@abcd.com"},
			"ab***@abcd.com",
		},
		{
			"test",
			fields{postClient: nil},
			args{"ab@abcd.com"},
			"a***@abcd.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := &emailAuthentication{
				postClient: tt.fields.postClient,
				logger:     l.NewNopLoggerWrapper().GetWrapperWithContext(),
			}
			if got := ea.makeMaskSafeMail(context.Background(), tt.args.mail); got != tt.want {
				t.Errorf("makeMaskSafeMail() = %v, want %v", got, tt.want)
			}
		})
	}
}
