package services

import (
	_ "bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

type Config struct {
	KUser struct {
		TableName     string `json:"table_name"`
		JwtExpireTime int    `json:"jwt_expire_time"`
		JwtSecretKey  string `json:"jwt_secret_key"`
	} `json:"kuser"`
}

type User struct {
	ID uint `gorm:"primaryKey"`
	Username string `gorm:"size:255; not null; unique"`
	Email string `gorm:"size:255; not null; unique"`
	Password string `gorm:"size:255; not null"`
	IsActive bool `gorm:"not null"`
}

func (User) TableName() string {
	return config.KUser.TableName
}

type Claims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}


var config Config
var db *gorm.DB

// functions allow to load external database connection
func SetDB(targetDB *gorm.DB) {
	db = targetDB
}

func GetDB() *gorm.DB {
	return db
}

// Load Config files
func LoadConfig() error {
	pwd, _ := os.Getwd()
	file,err := os.Open(path.Join(pwd, "config.json"))
	if err != nil {
		return err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return err
	}

	return nil
}

// Database initializer
func InitServices() error {
	err := LoadConfig()
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&User{})
	if err != nil {
		return err
	}
	return nil
}

// Services Handlers
func CreateUser(user *User) error {
	return db.Create(user).Error
}

func GetUserByUsername(username string) (*User, error) {
	var user User
	err := db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	user.Password = ""
	return &user, nil
}

func GetUserByID(userID uint) (*User, error) {
	var user User
	err := db.Where("username = ?", userID).First(&user).Error
	if err != nil {
		return nil, err
	}
	user.Password = ""
	return &user, nil
}

func getPasswordByUsername(username string) (string, error) {
	var user User
	err := db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return "", err
	}
	user.Password = ""
	return user.Password, nil
}

func GenerateJWT(username string, password string) (string, error) {
	// set expiration
	expirationTime := time.Now().Add(time.Duration(config.KUser.JwtExpireTime) * time.Hour)

	// create claims
	claims := &Claims{
		Username: username,
		Password: password,
		StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
	}

	// generate token
	var convertedSecret = []byte(config.KUser.JwtSecretKey)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(convertedSecret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ValidateJWT(token string) (*Claims, error) {
	claims := &Claims{}

	// parse token
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		var secr = []byte(config.KUser.JwtSecretKey)
		return secr, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, fmt.Errorf("invalid token")
		}
		return nil, fmt.Errorf("unable to parse token")
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func LoginWithUsername(username string, password string) (bool, string, error) {
	realPass, err := getPasswordByUsername(username)
	if err != nil {
		return false, "", err
	}
	if realPass == password {
		return true, "", nil
	} else {
		// generate jwt
		token, err := GenerateJWT(username, password)
		if err != nil {
			return false, "", err
		}
		return true, token, nil
	}
}

func LoginWithToken(token string) (bool, error) {
	tokenClaims, err := ValidateJWT(token)
	if err != nil {
		return false, err
	}
	actualPassword, err := getPasswordByUsername(tokenClaims.Username)
	if err != nil {
		return false, err
	}
	if actualPassword == tokenClaims.Password {
		return true, nil
	} else {
		return false, nil
	}
}

func UpdateUser(user *User) error {
	return db.Save(user).Error
}

func DeleteUser(id uint) error {
	return db.Delete(&User{}, id).Error
}

func ListUsers() ([]User, error) {
	var users []User
	err := db.Find(&users).Error
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(users); i++ {
		users[i].Password = ""
	}
	return users, nil
}