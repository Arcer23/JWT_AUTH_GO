package routes

import (
	controller "github.com/Arcer23/jwt-go-gin-mongodb/controllers"
	middleware "github.com/Arcer23/jwt-go-gin-mongodb/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incoming_Routes *gin.Engine){
	incoming_Routes.Use(middleware.Authenticate())
	incoming_Routes.GET("/users", controller.GetUsers())
	incoming_Routes.GET("/users/:user_id", controller.GetUser())
}