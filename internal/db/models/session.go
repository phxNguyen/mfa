package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type SessionModel struct {
	ID           primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	UserID       primitive.ObjectID `json:"userId" bson:"user_id"`
	AccessToken  string             `json:"accessToken" bson:"access_token"`
	RefreshToken string             `json:"refreshToken" bson:"refresh_token"`
	CreatedAt    time.Time          `json:"createdAt" bson:"created_at"`
}
