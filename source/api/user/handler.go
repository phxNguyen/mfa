package user

import (
	"app/source/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"log"
	"net/http"
)

type Handle struct {
	service *Service
}

func New(s *Service) *Handle {
	return &Handle{
		service: s,
	}
}

func (ins *Handle) Apply(r *gin.Engine) {
	r.POST("/login", ins.login)
	r.POST("/logout", middlewares.RequireAuth, ins.logout)
	r.POST("/refresh-token", ins.refreshToken)

	// ins.generateMfaSecret Generates an MFA secret for a user and returns it as a string
	// and as base64 encoded QR code image.
	r.POST("/mfa/generate-secret", middlewares.RequireAuth, ins.generateMfaSecret)
	r.POST("/mfa/active", middlewares.RequireAuth, ins.activeMfa)
	r.POST("/mfa/validate", middlewares.RequireAuth, ins.validateOTP)
	r.POST("/mfa/deactivate", middlewares.RequireAuth, ins.deactivateMfa)

}

func (ins *Handle) login(c *gin.Context) {
	// request process block
	request := LogInReq{
		trackingData: trackingData{
			ClientID:  c.DefaultQuery("cId", c.Request.UserAgent()),
			RequestID: c.DefaultQuery("reqId", uuid.NewString()),
		},
		Username: "", Password: "",
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest,
			LogInResp{request.trackingData, -1, err.Error(), logInResult{}})
		return
	}
	response, err := ins.service.Login(c.Request.Context(), &request)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, response, err.Error())
	}
	c.JSON(http.StatusOK, response)
}

func (ins *Handle) logout(c *gin.Context) {
	var (
		userAccess, _ = c.Get(middlewares.KeyUserContextAccess)
		request       = LogOutReq{
			trackingData{
				ClientID:  c.DefaultQuery("cId", c.Request.UserAgent()),
				RequestID: c.DefaultQuery("reqId", uuid.NewString()),
			},
		}
	)
	uCtx := userAccess.(middlewares.UserCtx)

	resp, err := ins.service.LogOut(c.Request.Context(), uCtx, &request)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, resp, err.Error())
	}

	c.JSON(http.StatusOK, resp)
}

func (ins *Handle) refreshToken(c *gin.Context) {
	var (
		request = RefreshTokenReq{
			trackingData{
				ClientID:  c.DefaultQuery("cId", c.Request.UserAgent()),
				RequestID: c.DefaultQuery("reqId", uuid.NewString()),
			},
			"",
		}
	)
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest,
			RefreshTokenResp{request.trackingData, -1, err.Error(), logInResult{}})
		return
	}

	resp, err := ins.service.RefreshToken(c.Request.Context(), &request)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, resp, err.Error())
	}
	if resp.Code == 41 || resp.Code == 43 {
		c.JSON(http.StatusUnauthorized, resp)
	} else {
		c.JSON(http.StatusOK, resp)
	}
}

func (ins *Handle) generateMfaSecret(c *gin.Context) {
	var (
		userAccess, _ = c.Get(middlewares.KeyUserContextAccess)
		request       = GenSecretMFAReq{
			trackingData{
				c.DefaultQuery("cId", c.Request.UserAgent()),
				c.DefaultQuery("reqId", uuid.NewString())},
		}
	)
	uCtx := userAccess.(middlewares.UserCtx)

	resp, err := ins.service.GenerateSecretMFA(c.Request.Context(), &request, uCtx)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, resp, err.Error())
	}
	if resp.Code == 41 || resp.Code == 43 {
		c.JSON(http.StatusUnauthorized, resp)
	} else {
		c.JSON(http.StatusOK, resp)
	}
}

func (ins *Handle) activeMfa(c *gin.Context) {
	var (
		userAccess, _ = c.Get(middlewares.KeyUserContextAccess)
		request       = ActiveMFAReq{
			trackingData: trackingData{
				c.DefaultQuery("cId", c.Request.UserAgent()),
				c.DefaultQuery("reqId", uuid.NewString())},
		}
	)
	uCtx := userAccess.(middlewares.UserCtx)
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": err})
		return
	}

	err := ins.service.ActivateMFA(c.Request.Context(), &request, uCtx)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, err.Error())
	}

	c.JSON(http.StatusOK, gin.H{"ok": "ok"})

}

func (ins *Handle) validateOTP(c *gin.Context) {
	var (
		userAccess, _ = c.Get(middlewares.KeyUserContextAccess)
		request       = ValidateOTPReq{
			trackingData: trackingData{
				c.DefaultQuery("cId", c.Request.UserAgent()),
				c.DefaultQuery("reqId", uuid.NewString())},
		}
	)
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	uCtx := userAccess.(middlewares.UserCtx)

	resp, err := ins.service.ValidateOTP(c.Request.Context(), uCtx, &request)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, resp, err.Error())
	}
	c.JSON(http.StatusOK, resp)
}

func (ins *Handle) deactivateMfa(c *gin.Context) {
	var (
		userAccess, _ = c.Get(middlewares.KeyUserContextAccess)
		_             = DeactivateMFAReq{
			trackingData{
				c.DefaultQuery("cId", c.Request.UserAgent()),
				c.DefaultQuery("reqId", uuid.NewString())},
		}
	)
	uCtx := userAccess.(middlewares.UserCtx)

	response, err := ins.service.DeactivateMFA(c.Request.Context(), uCtx)
	if err != nil {
		log.Printf("Path: %s, Response: %+v, Error: %s", c.Request.RequestURI, err.Error())
		c.JSON(http.StatusOK, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, response)

}
