package net

import (
	"context"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const (
	defaultAddr string = "0.0.0.0:8080"
)

type Engine struct {
	http.Server
	HandlerEngine *gin.Engine
}

func (ins *Engine) UseLogWriter(w io.Writer) {
	ins.HandlerEngine.Use(gin.LoggerWithWriter(w))
}

func (ins *Engine) UseCors(c cors.Config) {
	handlerFunc := cors.New(c)
	ins.HandlerEngine.Use(handlerFunc)
}

func (ins *Engine) AddHandler(apply func(engine *gin.Engine)) {
	if ins.HandlerEngine != nil {
		apply(ins.HandlerEngine)
		return
	}
	panic("server HandlerEngine Config invalid")
}

func (ins *Engine) Run(addr ...string) {
	var (
		interrupt = make(chan os.Signal)
	)
	if len(ins.Addr) > 0 {
		ins.Addr = addr[0]
	} else {
		ins.Addr = defaultAddr
	}
	if ins.HandlerEngine == nil {
		ins.HandlerEngine = gin.New()
	}
	// ghi đè server address
	if len(addr) > 0 {
		ins.Addr = addr[0]
	}
	defer func() {
		if recover() != nil {
			println("please call Engine.Init() function")
		}
	}()
	go func() {
		// apply HandlerEngine
		ins.Handler = ins.HandlerEngine
		println("Server starting ... addr:", ins.Addr)
		if err := ins.ListenAndServe(); err != nil {
			println("\r\n", err.Error())
		}
		interrupt <- os.Interrupt
	}()
	signal.Notify(interrupt, os.Interrupt, os.Kill)
	<-interrupt
	// shutdown server
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()
	_ = ins.Shutdown(ctx)
	os.Exit(0)
}
