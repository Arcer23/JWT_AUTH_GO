package routes

import (
	
	"github.com/gin-gonic/gin"
	"github.com/Arcer23/jwt-go-gin-mongodb/controllers"

)

func AuthRoutes(incoming_Routes *gin.Engine){
	incoming_Routes.POST("users/signup", controllers.SignUp)
	incoming_Routes.POST("users/login", controllers.Login)
}