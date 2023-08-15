package main

import (
	"app"
	"app/internal/lib/net"
	"app/internal/mongodb"
	"app/source/api/user"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	bindAddress           string
	mongoURI, mongoDbName string
)

func init() {
	//	Open the .env file
	if err := app.LoadEnvironmentVariables("./.env"); err != nil {
		log.Fatalf("- LoadEnvironmentVariables error: %s\n", err.Error())
	}
	mongoURI, mongoDbName = app.GetMongoURI()

	bindAddress = app.GetBindAddress()
	mongoURI, mongoDbName = app.GetMongoURI()

	// Khởi tạo kết nối MongoDB
	if mongodb.Conn == nil {
		println("Please implement value of mongodb.Connection!")
		os.Exit(1)
	} else {
		mongodb.Conn.Init(mongoURI, mongoDbName, 30*time.Second)
	}
}

func main() {

	apiEngine := &net.Engine{
		Server: http.Server{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		HandlerEngine: gin.New(),
	}

	apiEngine.UseLogWriter(os.Stdout)
	apiEngine.UseCors(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions, "*"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "*"},
		AllowCredentials: false,
		AllowWebSockets:  true,
		MaxAge:           12 * time.Hour,
	})

	userSvc := user.NewService()

	apiEngine.AddHandler(user.New(userSvc).Apply)
	apiEngine.Run(bindAddress)
}
