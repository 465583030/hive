package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"regexp"
	//s "strings"
	"time"

	"github.com/GeertJohan/go.rice"
	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var db *sql.DB

func init() {
	db, _ = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/bee?charset=utf8")
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.Ping()
}

func main() {
	e := echo.New()
	//e.Server.Addr = ":8080"

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CSRF())
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Gzip())

	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize:         4 << 10, // 4 KB
		DisableStackAll:   false,
		DisablePrintStack: false,
	}))
	// the file server for rice. "app" is the folder where the files come from.
	assetHandler := http.FileServer(rice.MustFindBox("app").HTTPBox())
	// serves the index.html from rice
	e.GET("/", echo.WrapHandler(assetHandler))

	// servers other static files
	//e.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))
	/*e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))*/

	//g := e.Group("/admin")
	/*g.Match([]string{"GET", "POST"}, "/login", login)
	g.Static("/", "/home/cox/ui/AdminLTE")
	g.File("/logo", "/run/media/cox/TOOLS/bee/bee_logo01.png")*/

	// Group level middleware
	/*admin := e.Group("/admin")

	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("oYZgeFONFh7HgQ"),
	}
	admin.Use(middleware.JWTWithConfig(config))
	admin.GET("", restricted)*/

	// Serve it like a boss
	//graceful.ListenAndServe(e.Server, 5*time.Second)
	e.GET("list", userList)

	admin := e.Group("/admin")
	admin.GET("/add", addAdminUser)
	admin.GET("/login", login)

	rule := e.Group("/rule")
	rule.GET("/store", store)

	fmt.Println("startAt:" + time.Now().String())
	e.Logger.Fatal(e.Start(":8080"))
	ExitFunc()
}

// jwtCustomClaims are custom claims extending default ones.
type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func store(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{
		"token": "",
	})
}

//用户登陆
func login(c echo.Context) error {
	username := c.QueryParam("username")
	password := c.QueryParam("password")
	alphaNumericRegex := regexp.MustCompile("^[a-zA-Z0-9]+$")

	if alphaNumericRegex.MatchString(username) || alphaNumericRegex.MatchString(password) {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"msg": http.StatusText(http.StatusBadRequest),
		})
	}

	if adminLogin(username) == password {
		// Set custom claims
		claims := &jwtCustomClaims{
			username,
			true,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			},
		}

		// Create token with claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Generate encoded token and send it as response.
		t, err := token.SignedString([]byte("oYZgeFONFh7HgQ"))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, echo.Map{
			"token": t,
		})
	}

	return echo.ErrUnauthorized
}

//不用
func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

//登陆用户欢迎页
func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name

	return c.JSON(http.StatusOK, "Welcome "+name+"!")
}

//添加一个新用户
func addAdminUser(c echo.Context) error {
	stmt, err := db.Prepare("INSERT INTO sys_user(username, passwd) VALUES(?, ?)")
	defer stmt.Close()

	if err != nil {
		log.Println(err)
		c.JSON(401, "添加用户失败")
	}
	stmt.Exec("cox", "123456")
	//stmt.Exec("testuser", "123123")
	return c.JSON(http.StatusOK, "添加了一个后台用户")
}

func adminLogin(username string) string {
	row := db.QueryRow("SELECT passwd FROM sys_user WHERE username = ?", username)
	var passwd string
	err := row.Scan(&passwd)
	checkErr(err)

	fmt.Println(passwd)
	return passwd
}

func userList(c echo.Context) error {
	rows, err := db.Query("SELECT * FROM sys_user limit 10")
	defer rows.Close()
	checkErr(err)

	columns, err := rows.Columns()
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, nil)
		} else {
			checkErr(err)
		}
		return c.JSON(http.StatusServiceUnavailable, nil)
	}
	scanArgs := make([]interface{}, len(columns))
	values := make([]interface{}, len(columns))
	for j := range values {
		scanArgs[j] = &values[j]
	}

	//records := make(map[int]interface{})
	//records := make([]interface{}, 0)
	var results []map[string]string

	for rows.Next() {
		record := make(map[string]string)
		//将行数据保存到record字典
		err = rows.Scan(scanArgs...)
		for i, col := range values {
			if col != nil {
				record[columns[i]] = string(col.([]byte))
			}
		}
		results = append(results, record)
	}
	//MarshalToString(results)
	return c.JSON(http.StatusOK, results)
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func ExitFunc() {
	defer db.Close()
	fmt.Println("i am exiting!")
}
