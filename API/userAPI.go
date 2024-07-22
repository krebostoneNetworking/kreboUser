package api

import (
	"net/http"
	"github.com/gin-gonic/gin"
	returnTypes "github.com/krebostoneNetworking/kReturnTypes"
	services "org.kimsse.kuser/Services"
)

type LoginRequestBody struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginTokenRequestBody struct {
	Token    string	`json:"token"    binding:"required"`
}

func createUserHandler(c *gin.Context) {
	var user services.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, returnTypes.GenGinHWithoutData(http.StatusBadRequest, "Error parsing objects"))
		return
	}
	if err := services.CreateUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, returnTypes.GenGinHWithData(http.StatusInternalServerError, "Unable to create user", err))
		return
	}
	c.JSON(http.StatusCreated, returnTypes.GenGinHWithoutData(http.StatusCreated, "Success"))
}

func loginUserHandler(c *gin.Context) {
	var req LoginRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, returnTypes.GenGinHWithData(http.StatusBadRequest, "Error parsing objects", err))
	}
	var success bool
	var userToken string
	var err error
	if success, userToken, err = services.LoginWithUsername(req.Username, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, returnTypes.GenGinHWithData(http.StatusInternalServerError, "Unable to login", err))
	}

	// success
	if success {
		c.JSON(http.StatusOK, returnTypes.GenGinHWithData(http.StatusOK, "Login successfully", userToken))
	} else {
		c.JSON(http.StatusBadRequest, returnTypes.GenGinHWithoutData(http.StatusBadRequest, "Wrong username or password"))
	}
}

func loginUserWithTokenHandler(c *gin.Context) {
	var req LoginTokenRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, returnTypes.GenGinHWithoutData(http.StatusBadRequest, "Missing arguments"))
	}
	var success bool
	var err error
	var newToken string
	if success, newToken, err = services.LoginWithToken(req.Token); err != nil {
		c.JSON(http.StatusInternalServerError, returnTypes.GenGinHWithoutData(http.StatusInternalServerError, "Unable to parse token"))
	}

	if success {
		
	}
}