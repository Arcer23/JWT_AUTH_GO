package middleware

import (
	"fmt"
	helper "github.com/Arcer23/jwt-go-gin-mongodb/helpers"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("unauthorized header")})
			c.Abort()
			return
		}
		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
			c.Abort()
			return
		}
		c.Set("email", claims.Email)
		c.Set("first_name", claims.First_name)
		c.Set("last_name", claims.Last_name)
		c.Set("uid ", claims.Uid)
		c.Set("user_type", claims.User_type)
		c.Next()

	}

}
