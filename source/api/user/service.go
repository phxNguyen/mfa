package user

import (
	"app/internal/auth"
	"errors"
	"go.mongodb.org/mongo-driver/mongo"
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
