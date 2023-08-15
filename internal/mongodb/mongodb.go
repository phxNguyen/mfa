package mongodb

import (
	"app/internal/lib/database"
	"app/internal/mongodb/db"
	"time"
)

var Conn = new(DB)

type DB struct {
	Session *db.LoginSession
	User    *db.User
}

func (ins *DB) Init(uri, dbName string, timeout time.Duration) {
	Conn = newConn(uri, dbName, timeout)
}

func newConn(uri, dbName string, timeout time.Duration) *DB {
	connection, err := database.MongoConnect(uri, dbName, timeout)
	if err != nil {
		panic(err)
	}
	return &DB{
		db.NewLoginSession(connection),
		db.NewUser(connection),
	}
}
