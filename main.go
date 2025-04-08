package main

import (
	"os"

	routes "github.com/Arcer23/jwt-go-gin-mongodb/routes"
	"github.com/gin-gonic/gin"
)

func main() {

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	r := gin.Default()
	r.Use(gin.Logger())

	routes.AuthRoutes(r)
	routes.UserRoutes(r)

	r.GET("/api-1", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "hi"})
	})

	r.Run(":" + port)
}
