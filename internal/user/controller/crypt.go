package controller

import "github.com/jiuzhou-zhao/go-fundamental/cryptutils"

func (c *Controller) passEncrypt(content string) (string, error) {
	return cryptutils.HMacSHa256(c.cfg.PwdSecret, content)
}
