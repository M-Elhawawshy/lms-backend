package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func (app *Application) routes(e *echo.Echo) {

	standard := []echo.MiddlewareFunc{middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper:          nil,
		Format:           "{time=${time_custom}, method=${method}, uri=${uri}, status=${status}, latency=${latency_human}, bytes_in=${bytes_in}, bytes_out=${bytes_out}, remote_ip=${remote_ip}}\n",
		CustomTimeFormat: "2006-01-02 15:04:05",
		CustomTagFunc:    nil,
		Output:           nil,
	}), middleware.Recover()}

	group := e.Group("/auth", standard...)
	group.POST("/signup", app.signUpHandler)
	group.POST("/login", app.loginHandler)
	group.POST("/logout", app.logoutHandler)
	group.POST("/refresh", app.refreshToken)

}
