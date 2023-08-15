package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type UserModel struct {
	ID        primitive.ObjectID   `json:"id,omitempty" bson:"_id,omitempty"`
	Username  string               `json:"username" bson:"username"`
	Password  string               `json:"-" bson:"password"`
	Sessions  []primitive.ObjectID `json:"-" bson:"sessions"`
	CreatedAt time.Time            `json:"createdAt" bson:"created_at"`
}
