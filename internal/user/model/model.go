package model

import (
	"errors"
	"math"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/sbasestarter/db-orm/go/user"
	userpb "github.com/sbasestarter/proto-repo/gen/protorepo-user-go"
	"github.com/sbasestarter/user/internal/user/controller/factory"
	"github.com/sgostarter/libeasygo/cuserror"
	"xorm.io/xorm"
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

func (m *Model) SetUser2FaKey(userID int64, key string) (err error) {
	_, err = m.db.Where(user.OUserAuthentication.EqUserId(), userID).
		Cols(user.OUserAuthentication.Token2fa()).Update(&user.UserAuthentication{
		Token2fa: key,
	})

	return
}

func (m *Model) GetUser2FaKey(userID int64) (key string, err error) {
	userAuthentication := &user.UserAuthentication{}
	exists, err := m.db.Where(user.OUserAuthentication.EqUserId(), userID).Get(userAuthentication)

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

func (m *Model) GetUserInfo(userID int64) (*user.UserInfo, error) {
	var userInfo user.UserInfo
	exists, err := m.db.Where(user.OUserInfo.EqUserId(), userID).Get(&userInfo)

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
	// nolint: nestif
	if err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) {
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
		var me *mysql.MySQLError
		if errors.As(err, &me) {
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

func (m *Model) UpdateUserPassword(userID int64, newPassword string) error {
	_, err := m.db.Where(user.OUserAuthentication.EqUserId(), userID).Update(&user.UserAuthentication{
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

func (m *Model) GetUserDetailInfo(userID int64) (*UserDetail, *user.UserSource, error) {
	session := m.db.Table(user.OUserInfo.TableName())
	session = session.Join("LEFT", user.OUserAuthentication.TableName(),
		user.OUserAuthentication.UserIdWT()+" = "+user.OUserInfo.UserIdWT())
	session = session.Join("LEFT", user.OUserExt.TableName(),
		user.OUserExt.UserIdWT()+" = "+user.OUserInfo.UserIdWT())
	session = session.Where(user.OUserInfo.EqUserIdWT(), userID)

	userDetail := &UserDetail{}

	exists, err := session.Get(userDetail)
	if err != nil {
		return nil, nil, err
	}

	if !exists {
		return nil, nil, errors.New("not exists")
	}

	userSource := &user.UserSource{}
	exists, err = m.db.Table(user.OUserSource.TableName()).Where(user.OUserSource.EqUserId(), userID).Get(userSource)

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
		return cuserror.NewWithErrorMsg("no user")
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

type UserItem struct {
	user.UserInfo `xorm:"extends"`
	// nolint:govet
	user.UserAuthentication `xorm:"extends"`
	// nolint:govet
	user.UserSource `xorm:"extends"`
}

func (m *Model) getUserListSession(keyword string) *xorm.Session {
	session := m.db.Table(user.OUserInfo.TableName())
	session = session.Join("LEFT", user.OUserAuthentication.TableName(),
		user.OUserAuthentication.UserIdWT()+" = "+user.OUserInfo.UserIdWT())

	session = session.Join("LEFT", user.OUserSource.TableName(),
		user.OUserSource.UserIdWT()+" = "+user.OUserInfo.UserIdWT())
	if keyword != "" {
		session = session.Where(user.OUserInfo.NickNameWT()+" like ?'", "%"+keyword+"%")
		session = session.Or(user.OUserSource.UserNameWT()+" like ?'", "%"+keyword+"%")
	}

	return session
}

func (m *Model) GetUserList(start int64, limit int, keyword string) (int64, []*UserItem, error) {
	cnt, err := m.getUserListSession(keyword).Count()
	if err != nil {
		return 0, nil, err
	}

	session := m.getUserListSession(keyword)

	if limit > 0 && start >= 0 {
		session = session.Limit(limit, int(start))
	}

	session = session.Desc("id")

	var users []*UserItem

	err = session.Find(&users)
	if err != nil {
		return 0, nil, err
	}

	return cnt, users, nil
}

func (m *Model) SetUserPrivileges(userID int64, privileges int) error {
	_, err := m.db.Where(user.OUserInfo.EqUserId(), userID).Cols(user.OUserInfo.Privileges()).
		Update(&user.UserInfo{Privileges: privileges})

	return err
}

func (m *Model) DeleteUser(userID int64) error {
	session := m.db.NewSession()

	err := session.Begin()
	if err != nil {
		return err
	}

	_, err = session.Delete(&user.UserAuthentication{UserId: userID})
	if err != nil {
		return err
	}

	_, err = session.Delete(&user.UserExt{UserId: userID})
	if err != nil {
		return err
	}

	_, err = session.Delete(&user.UserInfo{UserId: userID})
	if err != nil {
		return err
	}

	_, err = session.Delete(&user.UserSource{UserId: userID})
	if err != nil {
		return err
	}

	_, err = session.Delete(&user.UserTrust{UserId: userID})
	if err != nil {
		return err
	}

	return session.Commit()
}
