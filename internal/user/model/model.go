package model

import (
	"errors"
	"math"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	"github.com/sbasestarter/db-orm/go/user"
	"github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/user/controller/factory"
)

const (
	errMySQLDupEntry = 1062

	UserTrustRegisterNumber = 6
	userTrustNumber         = 6
	userTrustMaxNumber      = math.MaxInt32 - 1000
)

type Model struct {
	db    *xorm.Engine
	utils factory.Utils
}

func NewModel(db *xorm.Engine, utils factory.Utils) *Model {
	return &Model{db: db, utils: utils}
}

func (m *Model) SetUser2FaKey(userId int64, key string) (err error) {
	_, err = m.db.Where(user.OUserAuthentication.EqUserId(), userId).
		Cols(user.OUserAuthentication.Token2fa()).Update(&user.UserAuthentication{
		Token2fa: key,
	})
	return
}

func (m *Model) GetUser2FaKey(userId int64) (key string, err error) {
	userAuthentication := &user.UserAuthentication{}
	exists, err := m.db.Where(user.OUserAuthentication.EqUserId(), userId).Get(userAuthentication)
	if err != nil {
		return
	}
	if !exists {
		err = errors.New("user not exists")
		return
	}
	key = userAuthentication.Token2fa
	return
}

func (m *Model) GetUserInfo(userId int64) (*user.UserInfo, error) {
	var userInfo user.UserInfo
	exists, err := m.db.Where(user.OUserInfo.EqUserId(), userId).Get(&userInfo)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("user not exists")
	}
	return &userInfo, nil
}

func (m *Model) NewUser(userName, userVe, passwordHash, nickName, avatar string) (userpb.UserStatus, *user.UserInfo, error) {
	session := m.db.NewSession()
	err := session.Begin()
	if err != nil {
		return userpb.UserStatus_US_INTERNAL_ERROR, nil, err
	}
	defer func() {
		_ = session.Rollback()
	}()

	retryCount := 0
	userInfo := &user.UserInfo{
		NickName: nickName,
		Avatar:   avatar,
		CreateAt: time.Now(),
	}
RETRY:
	_, err = session.Insert(userInfo)
	if err != nil {
		if me, ok := err.(*mysql.MySQLError); ok {
			// https://dev.mysql.com/doc/refman/5.7/en/error-messages-server.html
			if retryCount > 0 {
				return userpb.UserStatus_US_INTERNAL_ERROR, nil, err
			}
			if me.Number == errMySQLDupEntry {
				userInfo.NickName += "-" + m.utils.RandomString(6)
				retryCount++
				goto RETRY
			}
		}
		return userpb.UserStatus_US_INTERNAL_ERROR, nil, err
	}

	userSource := &user.UserSource{
		UserName: userName,
		UserVe:   userVe,
		UserId:   userInfo.UserId,
	}
	_, err = session.Insert(userSource)
	if err != nil {
		if me, ok := err.(*mysql.MySQLError); ok {
			// https://dev.mysql.com/doc/refman/5.7/en/error-messages-server.html
			if me.Number == errMySQLDupEntry {
				return userpb.UserStatus_US_USER_ALREADY_EXISTS, nil, err
			}
		}
		return userpb.UserStatus_US_INTERNAL_ERROR, nil, err
	}

	userAuthentication := &user.UserAuthentication{
		UserId:   userInfo.UserId,
		Password: passwordHash,
	}
	_, err = session.Insert(userAuthentication)
	if err != nil {
		return userpb.UserStatus_US_INTERNAL_ERROR, nil, err
	}

	userExt := &user.UserExt{
		UserId: userInfo.UserId,
	}
	if userVe == userpb.VerificationEquipment_VEMail.String() {
		userExt.Email = userName
	} else if userVe == userpb.VerificationEquipment_VEPhone.String() {
		userExt.Phone = userName
	}
	_, err = session.Insert(userExt)
	if err != nil {
		return userpb.UserStatus_US_INTERNAL_ERROR, nil, err
	}

	_ = session.Commit()
	return userpb.UserStatus_US_SUCCESS, userInfo, nil
}

func (m *Model) GetUserAuthentication(userID int64) (*user.UserAuthentication, error) {
	var userAuth user.UserAuthentication
	exists, err := m.db.Where(user.OUserAuthentication.EqUserId(), userID).Get(&userAuth)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &userAuth, nil
}

func (m *Model) MustUserSource(userName, userVe string) (*user.UserSource, error) {
	userSource := &user.UserSource{}
	exists, err := m.db.Where(user.OUserSource.EqUserName(), userName).And(user.OUserSource.EqUserVe(),
		userVe).Get(userSource)
	if err != nil {
		return nil, err
	}
	if exists {
		return userSource, nil
	}
	userSource.UserName = userName
	userSource.UserVe = userVe
	_, err = m.db.Insert(userSource)
	if err != nil {
		return nil, err
	}
	return userSource, nil
}

func (m *Model) GetUserIDBySource(userName, userVe string) (int64, error) {
	userSource := &user.UserSource{}
	exists, err := m.db.Where(user.OUserSource.EqUserName(), userName).And(user.OUserSource.EqUserVe(),
		userVe).Get(userSource)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	return userSource.UserId, nil
}

func (m *Model) UserTrustInc(userID int64, ip string, incNum int) error {
	// 为了简单，不处理多IP同时登陆
	userTrust := user.UserTrust{}
	exists, err := m.db.Where(user.OUserTrust.EqUserId(), userID).And(user.OUserTrust.EqIp(), ip).Get(&userTrust)
	if err != nil {
		return err
	}
	if !exists {
		userTrust.UserId = userID
		userTrust.Ip = ip
		userTrust.Cnt = incNum
		_, err = m.db.Insert(userTrust)
		if err != nil {
			return err
		}
		return nil
	}

	if userTrust.Cnt >= userTrustMaxNumber {
		return nil
	}
	_, err = m.db.Where(user.OUserTrust.EqUserId(), userID).And(user.OUserTrust.EqIp(), ip).
		Update(&user.UserTrust{
			Cnt: userTrust.Cnt + incNum,
		})
	return err
}

func (m *Model) IsUserTrust(userID int64, ip string) (bool, error) {
	userTrust := user.UserTrust{}
	exists, err := m.db.Where(user.OUserTrust.EqUserId(), userID).And(user.OUserTrust.EqIp(), ip).Get(&userTrust)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	return userTrust.Cnt >= userTrustNumber, nil
}

func (m *Model) UpdateUserPassword(userId int64, newPassword string) error {
	_, err := m.db.Where(user.OUserAuthentication.EqUserId(), userId).Update(&user.UserAuthentication{
		Password: newPassword,
	})
	return err
}

type UserDetail struct {
	user.UserInfo `xorm:"extends"`
	// nolint:govet
	user.UserAuthentication `xorm:"extends"`
	// nolint:govet
	user.UserExt `xorm:"extends"`
}

func (m *Model) GetUserDetailInfo(userId int64) (*UserDetail, *user.UserSource, error) {
	session := m.db.Table(user.OUserInfo.TableName())
	session = session.Join("LEFT", user.OUserAuthentication.TableName(),
		user.OUserAuthentication.UserIdWT()+" = "+user.OUserInfo.UserIdWT())
	session = session.Join("LEFT", user.OUserExt.TableName(),
		user.OUserExt.UserIdWT()+" = "+user.OUserInfo.UserIdWT())
	session = session.Where(user.OUserInfo.EqUserIdWT(), userId)

	userDetail := &UserDetail{}
	exists, err := session.Get(userDetail)
	if err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, nil, errors.New("not exists")
	}

	userSource := &user.UserSource{}
	exists, err = m.db.Table(user.OUserSource.TableName()).Where(user.OUserSource.EqUserId(), userId).Get(userSource)
	if err != nil || !exists {
		return userDetail, nil, err
	}
	return userDetail, userSource, err
}

func (m *Model) UpdateUserInfo(userID int64, avatar, nickName string) error {
	if avatar == "" && nickName == "" {
		return nil
	}
	var userInfo user.UserInfo
	exists, err := m.db.Where(user.OUserInfo.EqUserId(), userID).Get(&userInfo)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("no user")
	}
	_, err = m.db.Table(user.OUserInfo.TableName()).Where(user.OUserInfo.EqUserId(), userID).Update(&user.UserInfo{
		Avatar:   avatar,
		NickName: nickName,
	})
	return err
}

func (m *Model) UpdateUserExt(userID int64, phone, email, weChat string) error {
	if phone == "" && email == "" && weChat == "" {
		return nil
	}
	_, err := m.db.Table(user.OUserExt.TableName()).Where(user.OUserExt.EqUserId(), userID).Update(&user.UserExt{
		Email:  email,
		Phone:  phone,
		Wechat: weChat,
	})
	return err
}
