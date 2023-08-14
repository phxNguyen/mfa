package db

import (
	"app/internal"
	"app/internal/db/models"
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"time"
)

type User struct {
	co *mongo.Collection
}

func NewUser(db *mongo.Database) *User {
	return &User{
		co: internal.MongoInit(
			db, "users",
		),
	}
}

func (ins *User) Count(ctx context.Context, filter interface{}) int64 {
	documents, err := ins.co.CountDocuments(ctx, filter)
	if err != nil {
		log.Fatal("cannot count", err)
	}
	return documents
}

func (ins *User) CreateUser(ctx context.Context, userName string, passWord string) (primitive.ObjectID, error) {
	result, err := ins.co.InsertOne(ctx, &models.UserModel{
		Username:  userName,
		Password:  passWord,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return primitive.NilObjectID, err
	}

	return result.InsertedID.(primitive.ObjectID), nil
}

func (ins *User) FindByID(ctx context.Context, id primitive.ObjectID) (*models.UserModel, error) {
	var (
		filter = bson.M{"_id": id}
		tmp    models.UserModel
	)
	if err := ins.co.FindOne(ctx, filter).Decode(&tmp); err != nil {
		return nil, err
	}
	return &tmp, nil
}

func (ins *User) Find(ctx context.Context, userName, pwd string) (*models.UserModel, error) {
	var (
		filter = bson.M{
			"username": userName,
			"password": pwd,
		}
		tmp *models.UserModel
	)
	result := ins.co.FindOne(ctx, filter)

	if err := result.Decode(&tmp); err != nil {
		return nil, err
	}
	return tmp, nil
}

func (ins *User) PushSession(ctx context.Context, uuid, sessionID primitive.ObjectID) error {
	var (
		filter = bson.M{
			"_id": uuid,
		}
		update = bson.M{
			"$set": bson.M{ // only login with 1 device
				"sessions": []primitive.ObjectID{sessionID},
			},
		}
	)
	if _, err := ins.co.UpdateOne(ctx, filter, update, nil); err != nil {
		return err
	} else {
		return nil
	}
}

func (ins *User) RevokeSession(ctx context.Context, uuid, sessionID primitive.ObjectID) error {
	var (
		update = bson.M{
			"$pull": bson.M{
				"sessions": sessionID,
			},
		}
	)
	if _, err := ins.co.UpdateByID(ctx, uuid, update, nil); err != nil {
		return err
	} else {
		return nil
	}
}

func (ins *User) ValidateSession(ctx context.Context, sessionID primitive.ObjectID) (bool, error) {
	var (
		filter = bson.M{
			"sessions": sessionID,
		}
	)
	n, err := ins.co.CountDocuments(ctx, filter)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (ins *User) ChangePassword(ctx context.Context, id primitive.ObjectID, pwd string) error {
	var (
		update = bson.M{
			"$set": bson.M{
				"password": pwd,
			},
		}
	)
	_, err := ins.co.UpdateByID(ctx, id, update)
	if err != nil {
		return err
	}
	return nil
}
