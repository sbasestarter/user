package controller

import (
	"bytes"
	"context"
	"image/color"
	"image/png"
	"time"

	"github.com/issue9/identicon"
	filepb "github.com/sbasestarter/proto-repo/gen/protorepo-file-go"
)

func (c *Controller) filterUserAvatar(avatar string) string {
	if avatar == "" {
		avatar = c.cfg.DefaultUserAvatar
	}

	return avatar
}

func (c *Controller) newAvatar(ctx context.Context, username string) (string, error) {
	img, err := identicon.Make(128, color.RGBA{}, color.RGBA{0, 0, 0, 255}, []byte(username))
	if err != nil {
		c.logger.Errorf(ctx, "avatar generate failed: %v", err)

		return "", err
	}

	buf := new(bytes.Buffer)

	err = png.Encode(buf, img)
	if err != nil {
		c.logger.Errorf(ctx, "avatar png encode failed: %v", err)

		return "", err
	}

	req := &filepb.UpdateFileRequest{
		FileName: "",
		Content:  buf.Bytes(),
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.fileCli.UpdateFile(ctx, req)
	if err != nil {
		c.logger.Errorf(ctx, "avatar update failed: %v", err)

		return "", err
	}

	return resp.GetFileUrl(), nil
}
