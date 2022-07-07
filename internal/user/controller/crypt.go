package controller

import "github.com/sgostarter/libeasygo/crypt"

func (c *Controller) passEncrypt(content string) (string, error) {
	return crypt.HMacSHa256(c.cfg.PwdSecret, content)
}
