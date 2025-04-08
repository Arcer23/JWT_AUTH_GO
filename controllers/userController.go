package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Arcer23/jwt-go-gin-mongodb/database"
	"github.com/Arcer23/jwt-go-gin-mongodb/helpers"
	helper "github.com/Arcer23/jwt-go-gin-mongodb/helpers"
	"github.com/Arcer23/jwt-go-gin-mongodb/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var UserCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var validate = validator.New()

func HashPassword(password string) string {
	err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect")
		check = false
	}
	return check, msg
}
func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}
		count, err := UserCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error while checking for the user"})
			return
		}
		password := HashPassword(*&user.Password)
		user.Password = password
		count, err = UserCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone number"})
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this phone number or email already exists"})
		}
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		token, refresh_token, _ := helper.GenerateAllTokens(*&user.Email, *&user.First_name, *&user.Last_name, *&user.User_Type, *&user.User_id)
		user.Token = token
		user.Refresh_Token = refresh_token

		resultInsertionNumber, insertErr := UserCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		err := UserCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "your email and passwrod is incorrect"})
			return
		}
		passwordValid, msg := VerifyPassword(*&user.Password, *&foundUser.Password)
		defer cancel()
		if passwordValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "usernotfound"})
			return
		}
		token, refreshToken, _ := helper.GenerateAllTokens(*&foundUser.Email, *&foundUser.First_name, foundUser.Last_name, foundUser.User_Type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = UserCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}
func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest,gin.H{"error":
		err.Error()})
		return
		}
		var ctx , cancel = context.WithTimeout(context.Background(), 100*time.Second);

		recordPerPage, err  := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1{
			recordPerPage = 10
		}
		page , err1 := strconv.Atoi(c.Query("page"));
		if err1 != nil || page < 1 {
			page =1 
		}
		startIndex := (page-1) * recordPerPage
		startIndex, err = strconv.Atoi(c.Query("startIndex"));

		matchStage := bson.D{{Key: "$match", Value: bson.D{}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: nil}}}}

		// Example usage of matchStage and groupStage to avoid "declared and not used" errors
		cursor, err := UserCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while fetching data"})
			defer cancel()
			return
		}
		var results []bson.M
		if err = cursor.All(ctx, &results); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while decoding data"})
			defer cancel()
			return
		}
		c.JSON(http.StatusOK, results)
	}
}
func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if err := helper.MatchUserTypeToUid(c, userID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} //ensuring if the user is admin or a normal user
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		err := UserCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&user)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
