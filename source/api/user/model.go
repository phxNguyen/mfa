package user

import (
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type trackingData struct {
	ClientID  string `json:"cId"`
	RequestID string `json:"reqId"`
}

type RegisterReq struct {
	trackingData
	Username string `json:"username"`
	Password string `json:"password"`
}

func (r RegisterReq) validate() error {

	return nil
}

type LogInReq struct {
	trackingData
	Username string `json:"username"`
	Password string `json:"password"`
}

func (r LogInReq) validate() error {
	if len(r.Username) == 0 || len(r.Password) == 0 {
		return errors.New("username or password cannot be blank")
	}
	return nil
}

type LogInResp struct {
	trackingData
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Result  logInResult `json:"result"`
}

type logInResult struct {
	UUID         primitive.ObjectID `json:"uuid"`
	TokenType    string             `json:"tokenType"`
	AccessToken  string             `json:"accessToken"`
	RefreshToken string             `json:"refreshToken"`
	ExpiresIn    int64              `json:"expiresIn"`
}

type RefreshTokenReq struct {
	trackingData
	RefreshToken string `json:"refreshToken"`
}

func (r RefreshTokenReq) Validate() error {
	if len(r.RefreshToken) < 5 {
		return errors.New("parameter RefreshToken invalid")
	}
	return nil
}

type RefreshTokenResp struct {
	trackingData
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Result  logInResult `json:"result"`
}

type LogOutReq struct {
	trackingData
}

type LogOutResp struct {
	trackingData
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ChangePasswordReq struct {
	trackingData
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (req *ChangePasswordReq) Validate() error {
	if len(req.CurrentPassword) == 0 || len(req.NewPassword) == 0 {
		return errors.New("currentPassword or newPassword invalid")
	}
	return nil
}

type ChangePasswordResp struct {
	trackingData
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type GenSecretMFAReq struct {
	trackingData
}

type GenSecretMFAResp struct {
	trackingData
	Code    int       `json:"code"`
	Message string    `json:"message"`
	Result  GenSecret `json:"result"`
}

type GenSecret struct {
	URI    string `json:"uri"`
	Issuer string `json:"issuer"`
	QR     []byte `json:"qr"`
}

type ValidateOTPReq struct {
	trackingData
	OTP string `json:"otp"`
}

type ActiveMFAReq struct {
	trackingData
	OTP string `json:"otp"`
}
type DeactivateMFAReq struct {
	trackingData
}

type DeactivateMFAResp struct {
}
