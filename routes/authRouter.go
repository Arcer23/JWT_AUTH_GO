package routes

import (
	
	"github.com/gin-gonic/gin"
	controller "github.com/Arcer23/jwt-go-gin-mongodb/controllers"

)

func AuthRoutes(incoming_Routes *gin.Engine){
	incoming_Routes.POST("users/signup", controller.SignUp())
	incoming_Routes.POST("users/login", controller.Login())
}