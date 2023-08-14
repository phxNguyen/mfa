package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

var (
	JwtSecret = func() []byte {
		key, err := rsa.GenerateKey(rand.Reader, 256)
		if err != nil {
			return nil
		}
		return x509.MarshalPKCS1PrivateKey(key)
	}()
)

type UserClaims struct {
	UUID     primitive.ObjectID
	Username string
	jwt.RegisteredClaims
}

func GenerateAccessToken(uuid primitive.ObjectID, username string, period time.Duration) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		UUID:     uuid,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(period)),
		},
	}).SignedString(JwtSecret)
}

func GenerateRefreshToken(period time.Duration) (
	string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(period)),
		},
	).SignedString(JwtSecret)
}

func ValidateAccessToken(accessToken string) (
	primitive.ObjectID, string, *jwt.RegisteredClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil {
		return primitive.NilObjectID, "", nil, err
	}
	if parsedToken == nil {
		return primitive.NilObjectID, "", nil, errors.New("can not parse token")
	}
	claims, ok := parsedToken.Claims.(*UserClaims)
	if !ok {
		return primitive.NilObjectID, "", nil, errors.New("token invalid")
	}

	return claims.UUID, claims.Username, &claims.RegisteredClaims, nil
}

func ValidateRefreshToken(refreshToken string) (*jwt.RegisteredClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if parsedToken == nil {
		return nil, errors.New("can not parse token")
	}
	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, errors.New("token invalid")
	}

	return claims, nil
}
