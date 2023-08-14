package utils

import (
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strings"
)

type Payload struct {
	Username string
	ID       string
	Role     string
	jwt.RegisteredClaims
}

var SecretKey = os.Getenv("SECRET_JWT")

func ValidateToken(tokenString string) (*Payload, error) {

	token, err := jwt.ParseWithClaims(
		tokenString,
		&Payload{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Payload)
	if !ok || !token.Valid {
		return nil, err
	}

	return claims, nil
}

func ExtractToken(bearerToken string) string {
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}
	return ""
}
