package middlewares

import (
	"app/internal/auth"
	"app/source/utils"
	"errors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"net/http"
	"time"
)

type UserCtx struct {
	SessionID    primitive.ObjectID `json:"-"`
	UUID         primitive.ObjectID ` json:"-"`
	Username     string             `json:"-"`
	AccessToken  string             `json:"-"`
	RefreshToken string             `json:"-"`
}

const (
	KeyUserContextAccess = "ACCESS-INFO"
)

func RequireAuth(c *gin.Context) {

	bearerToken := c.Request.Header.Get("Authorization")
	accessToken := utils.ExtractToken(bearerToken)
	if accessToken == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	session, err := mongodb.Conn.Session.GetByAT(c.Request.Context(), accessToken)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	ready, err := mongodb.Conn.User.ValidateSession(c.Request.Context(), session.ID)
	if !ready || errors.Is(err, mongo.ErrNoDocuments) {
		log.Println("session expired")

		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	uuid, username, claims, err := auth.ValidateAccessToken(accessToken)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims.ExpiresAt.Before(time.Now()) || claims.IssuedAt.After(time.Now()) {
		// Token expired
		log.Println("this token has expired")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if session.UserID != uuid {
		log.Println("bad token")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Set(KeyUserContextAccess,
		UserCtx{session.ID,
			uuid,
			username,
			session.AccessToken,
			session.RefreshToken})

	c.Next()
}
