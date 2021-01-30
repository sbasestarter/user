package model

import (
	"context"
	"os"
	"testing"

	"github.com/jiuzhou-zhao/go-fundamental/dbtoolset"
	"github.com/jiuzhou-zhao/go-fundamental/loge"
	"github.com/sbasestarter/db-orm/go/user"
	"github.com/sbasestarter/user/internal/config"
	"github.com/sbasestarter/user/internal/user/helper"
	"github.com/sgostarter/libconfig"
)

var TestDbToolset *dbtoolset.DBToolset
var TestModel *Model

const (
	TestUserId = 1000
)

func TestMain(m *testing.M) {
	logger := &loge.ConsoleLogger{}

	var cfg config.Config
	_, _ = libconfig.Load("config", &cfg)

	TestDbToolset, _ = dbtoolset.NewDBToolset(context.Background(), &cfg.DBConfig, logger)

	TestModel = NewModel(TestDbToolset.GetMySQL(), helper.NewUtilsImpl())

	_, _ = TestDbToolset.GetMySQL().Where("true").Delete(&user.UserAuthentication{})
	_, _ = TestDbToolset.GetMySQL().Where("true").Delete(&user.UserSource{})
	_, _ = TestDbToolset.GetMySQL().Where("true").Delete(&user.UserInfo{})
	_, _ = TestDbToolset.GetMySQL().Where("true").Delete(&user.UserExt{})
	_, _ = TestDbToolset.GetMySQL().Insert(&user.UserAuthentication{
		UserId:   TestUserId,
		Password: "",
		Token2fa: "",
	})

	os.Exit(m.Run())
}
