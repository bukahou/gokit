package localauth

import (
	"context"
	"time"
)

// DeviceReissuer 在「吊销全部会话」之后为当前设备重签一对新凭证。
//
// 改密 (批次三) 与改邮箱 (批次四) 都需要它 —— 第二次出现就抽出来,
// 免得两处对"refresh 签成功但 access 签失败"的处置各写一套然后漂移。
type DeviceReissuer struct {
	sessions *SessionGuard
	issuer   AccessTokenIssuer
}

// Reissued 是重签结果。
type Reissued struct {
	RefreshToken string
	Session      SessionRecord
	// AccessToken 仅在配了 AccessTokenIssuer 且签发成功时非空。
	// ⚠️ 为空【不等于】重签失败 —— 前端拿 refresh 换一次即可。
	AccessToken     string
	AccessExpiresAt time.Time
	// AccessErr 记录 access token 签发失败的原因 (refresh 已成功)。
	AccessErr error
}

// NewDeviceReissuer 构造。issuer 可为 nil (只重签 refresh)。
func NewDeviceReissuer(sessions *SessionGuard, issuer AccessTokenIssuer) *DeviceReissuer {
	return &DeviceReissuer{sessions: sessions, issuer: issuer}
}

// Reissue 建一条新会话并 (若配了) 签一张 access token。
//
// ⚠️ 返回 error 只表示 refresh 都没签出来 —— 那时用户需要重新登录。
// access 签发失败不算错误: 记在 AccessErr, 由调用方决定记什么级别。
func (r *DeviceReissuer) Reissue(ctx context.Context, userID, device, ip string) (Reissued, error) {
	tok, rec, err := r.sessions.Issue(ctx, SessionRecord{UserID: userID, DeviceInfo: device, ClientIP: ip})
	if err != nil {
		return Reissued{}, err
	}
	out := Reissued{RefreshToken: tok, Session: rec}
	if r.issuer != nil {
		at, exp, aerr := r.issuer(ctx, userID, rec.ID)
		if aerr != nil {
			out.AccessErr = aerr
		} else {
			out.AccessToken, out.AccessExpiresAt = at, exp
		}
	}
	return out, nil
}
