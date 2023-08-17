package user

import (
	"app/internal/auth"
	"app/internal/mongodb"
	"app/internal/mongodb/db/models"
	"app/source/middlewares"
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/dgryski/dgoogauth"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"rsc.io/qr"
	"time"
)

type Service struct {
	db *mongodb.DB
}

func NewService() *Service {
	return &Service{
		db: mongodb.Conn,
	}
}

const (
	tokenExpired        = 3600 * time.Second
	refreshTokenExpired = 10 * 24 * time.Hour
	secretSize          = 10
)

func (ins *Service) Login(ctx context.Context, request *LogInReq) (*LogInResp, error) {
	err := request.validate()
	if err != nil {
		return nil, err
	}
	user, err := ins.db.User.Find(ctx, request.Username, request.Password)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return &LogInResp{request.trackingData,
				41, "USERNAME OR PASSWORD INCORRECT", logInResult{}}, err
		}
		return nil, err
	}
	accessToken, err := auth.GenerateAccessToken(user.ID, user.Username, tokenExpired)
	if err != nil {
		return nil, err
	}

	refreshToken, err := auth.GenerateRefreshToken(refreshTokenExpired)
	if err != nil {
		return nil, err
	}

	//gen new session
	sessionID, err := ins.db.Session.CreateNewSession(ctx, user.ID, accessToken, refreshToken)
	if err != nil {
		return nil, err
	}
	//update session to user
	if err := ins.db.User.PushSession(ctx, user.ID, sessionID); err != nil {
		return nil, err
	}
	result := logInResult{
		UUID:         user.ID,
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(tokenExpired / time.Second),
	}

	return &LogInResp{
		trackingData: request.trackingData,
		Code:         0,
		Message:      "",
		Result:       result,
	}, nil
}

func (ins *Service) LogOut(ctx context.Context, uCtx middlewares.UserCtx, request *LogOutReq) (LogOutResp, error) {
	//remove sessionId from user
	if err := ins.db.User.RevokeSession(ctx, uCtx.UUID, uCtx.SessionID); err != nil {
		return LogOutResp{request.trackingData,
			53, "DATABASE_ERROR"}, err
	}
	return LogOutResp{request.trackingData,
		0, ""}, nil
}

func (ins *Service) RefreshToken(ctx context.Context, request *RefreshTokenReq) (RefreshTokenResp, error) {
	if err := request.Validate(); err != nil {
		return RefreshTokenResp{request.trackingData,
			40, "INVALID", logInResult{}}, err
	}
	//verify refresh token
	rt, err := auth.ValidateRefreshToken(request.RefreshToken)
	if err != nil {
		return RefreshTokenResp{request.trackingData,
			41, "REFRESH_TOKEN_INVALID", logInResult{}}, err
	}
	if rt.ExpiresAt.Before(time.Now()) {
		return RefreshTokenResp{request.trackingData,
			43, "REFRESH_TOKEN_EXPIRED", logInResult{}}, err
	}
	//
	session, err := ins.db.Session.GetByRT(ctx, request.RefreshToken)
	if err != nil {
		return RefreshTokenResp{request.trackingData,
			53, "DATABASE_ERROR", logInResult{}}, err
	}
	user, err := ins.db.User.FindByID(ctx, session.UserID)
	if err != nil {
		return RefreshTokenResp{request.trackingData,
			53, "DATABASE_ERROR", logInResult{}}, err
	}
	//gen new user token
	accessToken, err := auth.GenerateAccessToken(user.ID, user.Username, tokenExpired)
	if err != nil {
		return RefreshTokenResp{request.trackingData,
			53, "GEN_ACCESS_TOKEN_FAILED", logInResult{}}, err
	}
	//update access token
	if err = ins.db.Session.UpdateAccessToken(ctx, session.ID, accessToken); err != nil {
		return RefreshTokenResp{request.trackingData,
			53, "DATABASE_ERROR", logInResult{}}, err
	}
	result := logInResult{
		UUID:         user.ID,
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		RefreshToken: request.RefreshToken,
		ExpiresIn:    int64(tokenExpired / time.Second),
	}
	return RefreshTokenResp{request.trackingData,
		0, "SUCCEED", result}, nil
}

func (ins *Service) GenerateSecretMFA(ctx context.Context, request *GenSecretMFAReq, uCtx middlewares.UserCtx) (*GenSecretMFAResp, error) {

	secret := genSecret(secretSize)
	issuer := "WeeDigitalAhihi"
	// authLink see more at https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	authLink := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, uCtx.Username, secret, issuer)

	code, err := qr.Encode(authLink, qr.H)
	if err != nil {

	}

	img := code.PNG()

	err = ins.db.User.UpdateMfaSecret(ctx, uCtx.UUID, secret)
	if err != nil {
		return &GenSecretMFAResp{
			request.trackingData, 1, "DB Err", GenSecret{},
		}, err
	}

	return &GenSecretMFAResp{
		trackingData: request.trackingData,
		Code:         0,
		Message:      "",
		Result: GenSecret{
			URI:    authLink,
			Issuer: issuer,
			QR:     img,
		},
	}, nil

}

func (ins *Service) ActivateMFA(ctx context.Context, req *ActiveMFAReq, uCtx middlewares.UserCtx) error {

	user, err := ins.db.User.FindByID(ctx, uCtx.UUID)
	if err != nil {
		return err
	}
	// see more at https://github.com/dgryski/dgoogauth
	otpConfig := dgoogauth.OTPConfig{
		Secret:      user.MFASecret,
		HotpCounter: 0,
		WindowSize:  3,
	}

	valid, err := otpConfig.Authenticate(req.OTP)
	if err != nil || !valid {
		log.Printf("ActivateMFA err %s", err)
		return err
	}
	if err := ins.db.User.UpdateMfaActive(ctx, uCtx.UUID, true); err != nil {
		log.Printf("ActivateMFA err %s", err)
		return err
	}
	return nil
}

func (ins *Service) ValidateOTP(ctx context.Context, uCtx middlewares.UserCtx, req *ValidateOTPReq) (bool, error) {

	user, err := ins.db.User.FindByID(ctx, uCtx.UUID)
	if err != nil {
		log.Printf("ValidateOTP err %s", err)
		return false, err
	}

	// see more at https://github.com/dgryski/dgoogauth
	otpConfig := dgoogauth.OTPConfig{
		Secret:      user.MFASecret,
		HotpCounter: 0,
		WindowSize:  3,
	}

	valid, err := otpConfig.Authenticate(req.OTP)
	if err != nil {
		log.Printf("ValidateOTP err %s", err)
		return false, err
	}
	return valid, nil
}

func (ins *Service) DeactivateMFA(ctx context.Context, uCtx middlewares.UserCtx) (*models.UserModel, error) {
	if err := ins.db.User.UpdateMfaSecret(ctx, uCtx.UUID, ""); err != nil {
		return nil, err
	}
	if err := ins.db.User.UpdateMfaActive(ctx, uCtx.UUID, false); err != nil {
		return nil, err
	}
	user, err := ins.db.User.FindByID(ctx, uCtx.UUID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func genSecret(size int) string {
	data := make([]byte, size)
	rand.Read(data)
	return base32.StdEncoding.EncodeToString(data)
}
