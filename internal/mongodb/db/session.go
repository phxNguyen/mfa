package db

import (
	"app/internal/lib/database"
	"app/internal/mongodb/db/models"
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type LoginSession struct {
	co *mongo.Collection
}

func NewLoginSession(db *mongo.Database) *LoginSession {
	return &LoginSession{
		co: database.MongoInit(
			db,
			"login_sessions",
		),
	}
}

func (ins *LoginSession) CreateNewSession(ctx context.Context,
	userID primitive.ObjectID, accessToken, refreshToken string) (primitive.ObjectID, error) {
	if r, err := ins.co.InsertOne(ctx, &models.SessionModel{
		ID:           primitive.NewObjectID(),
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now(),
	}); err != nil {
		return primitive.NilObjectID, err
	} else {
		return r.InsertedID.(primitive.ObjectID), nil
	}
}

func (ins *LoginSession) GetByAT(ctx context.Context, accessToken string) (*models.SessionModel, error) {
	var (
		filter = bson.M{
			"access_token": accessToken,
		}
		session models.SessionModel
	)
	println(accessToken)
	if err := ins.co.FindOne(ctx, filter).Decode(&session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (ins *LoginSession) GetByRT(ctx context.Context, refreshToken string) (*models.SessionModel, error) {
	var (
		filter = bson.M{
			"refresh_token": refreshToken,
		}
		session models.SessionModel
	)
	if err := ins.co.FindOne(ctx, filter).Decode(&session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (ins *LoginSession) UpdateAccessToken(ctx context.Context, id primitive.ObjectID, accessToken string) error {
	var (
		filter = bson.M{
			"_id": id,
		}
		update = bson.M{
			"$set": bson.M{
				"access_token": accessToken,
			},
		}
	)
	if _, err := ins.co.UpdateOne(ctx, filter, update); err != nil {
		return err
	}
	return nil
}
