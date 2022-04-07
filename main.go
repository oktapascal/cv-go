package main

import (
	"bytes"
	"context"
	"cv/config"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// ONLY IMAGE VALIDATION
// image formats and magic numbers
var magicTable = map[string]string{
	"\xff\xd8\xff":      "image/jpeg",
	"\x89PNG\r\n\x1a\n": "image/png",
}

// GLOBAL VARIABLE
var JWT_SIGNING_METHOD = jwt.SigningMethodHS256
var AWS_REGION string
var AWS_ACCESS_KEY string
var AWS_SECRET_ACCESS_KEY string

// TYPE
type (
	User struct {
		Nik      string `json:"nik" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	jwtCustomClaims struct {
		Nik string `json:"nik"`
		jwt.StandardClaims
	}
	Response struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
	ResponseData struct {
		Status bool        `json:"status"`
		Data   interface{} `json:"data"`
	}
	CustomValidator struct {
		validator *validator.Validate
	}
	DataUser struct {
		Nama    string `json:"nama" validate:"required,max=200"`
		Jk      string `json:"jk" validate:"required,max=1"`
		Alamat  string `json:"alamat" validate:"required"`
		Jabatan string `json:"jabatan" validate:"required,max=100"`
	}
	ImageProject struct {
		Flag string `json:"flag"`
		No   string `json:"no"`
	}
	DataProject struct {
		ID        string `json:"id"`
		Nama      string `json:"nama" validate:"required,max=200"`
		Deskripsi string `json:"deskripsi" validate:"required"`
		PIC       string `json:"pic" validate:"required,max=20"`
		Images    []ImageProject
	}
	DeleteProjectImage struct {
		ID string `json:"id"`
		No string `json:"no" validate:"required"`
	}
)

func main() {
	server := echo.New()

	// INISIASI VIPER
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("app.config")

	err := viper.ReadInConfig()

	if err != nil {
		server.Logger.Fatal(err)
	}

	// MIDDLEWARE
	server.Use(middleware.Logger())
	server.Use(middleware.Recover())

	// CONNECT TO AWS
	session := ConnectToAws()

	// CUSTOM VALIDATOR
	server.Validator = &CustomValidator{validator: validator.New()}

	server.HTTPErrorHandler = func(err error, ctx echo.Context) {
		report, ok := err.(*echo.HTTPError)

		if !ok {
			report = echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if castedObject, ok := err.(validator.ValidationErrors); ok {
			for _, err := range castedObject {
				switch err.Tag() {
				case "required":
					report.Message = fmt.Sprintf("%s tidak boleh kosong.", err.Field())
				case "max":
					report.Message = fmt.Sprintf("%s tidak boleh melebihi %s karakter.", err.Field(), err.Param())
				}
			}
		}

		ctx.Logger().Error(report)
		ctx.JSON(report.Code, report)
	}

	// LOGIN
	server.POST("/login", Login)
	server.POST("/logout", Logout)
	// GROUP ROUTES
	authRoutes := server.Group("/api")

	// CUSTOM MIDDLEWARE
	authRoutes.Use(CheckCookieAccessToken)
	authRoutes.Use(CheckAuthorizationJwt)
	authRoutes.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			ctx.Set("session", session)
			return next(ctx)
		}
	})
	// MIDDLEWARE JWT
	jwtConfig := middleware.JWTConfig{
		Claims:      &jwtCustomClaims{},
		SigningKey:  []byte(viper.GetString("appKey.key")),
		TokenLookup: "cookie:access-token",
	}
	authRoutes.Use(middleware.JWTWithConfig(jwtConfig))

	authRoutes.GET("/user", Show)
	authRoutes.GET("/user-image", ShowImage)
	authRoutes.GET("/projects", IndexProject)
	authRoutes.GET("/check", CheckToken)
	authRoutes.POST("/user", Update)
	authRoutes.POST("/user-upload", uploadImage)
	authRoutes.POST("/project-simpan", StoreProject)
	authRoutes.POST("/project-upload", UpdateProject)
	authRoutes.POST("/project-upload", UploadImageProject)
	authRoutes.DELETE("/project-upload", DeleteImage)
	authRoutes.DELETE("/project", DeleteProject)

	server.Logger.Fatal(server.Start(":" + viper.GetString("server.port")))
}

// VALIDATOR
func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

// CONNECT TO AWS
func ConnectToAws() *session.Session {
	AWS_REGION = viper.GetString("aws.region")
	AWS_ACCESS_KEY = viper.GetString("aws.key")
	AWS_SECRET_ACCESS_KEY = viper.GetString("aws.secret")

	session, err := session.NewSession(
		&aws.Config{
			Region: aws.String(AWS_REGION),
			Credentials: credentials.NewStaticCredentials(
				AWS_ACCESS_KEY,
				AWS_SECRET_ACCESS_KEY,
				"",
			),
		})

	if err != nil {
		fmt.Println(err.Error())
	}

	return session
}

// CUSTOM MIDDLEWARE
func CheckCookieAccessToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		_, err := ctx.Cookie("access-token")

		if err != nil {
			res := &Response{
				Status:  false,
				Message: "Kamu tidak memiliki hak akses",
			}
			return ctx.JSON(http.StatusInternalServerError, res)
		}

		return next(ctx)
	}
}

func CheckAuthorizationJwt(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		myToken, _ := ctx.Cookie("access-token")

		check, err := jwt.Parse(myToken.Value, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("SIGNING METHOD INVALID")
			} else if method != JWT_SIGNING_METHOD {
				return nil, fmt.Errorf("SIGNING METHOD INVALID")
			}

			return []byte(viper.GetString("appKey.key")), nil
		})

		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, err.Error())
		}

		claims, ok := check.Claims.(jwt.MapClaims)

		if !ok || !check.Valid {
			return ctx.JSON(http.StatusInternalServerError, err.Error())
		}

		ctx.SetRequest(ctx.Request().WithContext(context.WithValue(ctx.Request().Context(), "user", claims)))
		return next(ctx)
	}
}

// HELPER
func CheckPasswordHash(value, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(value))

	return err == nil
}

func CheckIsImage(incipit []byte) string {
	incipitStr := []byte(incipit)

	for magic, mime := range magicTable {
		if strings.HasPrefix(string(incipitStr), magic) {
			return mime
		}
	}

	return ""
}

func GenerateProject() string {
	prefix := "PRJ"

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		defer panic(err.Error())
	}

	defer db.Close()

	var id *string
	q := "select top 1 id from cv_project order by id desc"

	err = db.QueryRow(q).Scan(&id)

	if err != nil && err != sql.ErrNoRows {
		defer panic(err.Error())
	}

	if err == sql.ErrNoRows {
		return fmt.Sprintf("%s1", prefix)
	}

	idNum := (*id)[3:]

	num, _ := strconv.ParseInt(idNum, 0, 8)
	num = num + 1

	return fmt.Sprintf("%s%o", prefix, num)
}

// HANDLERS //
func CheckToken(ctx echo.Context) (err error) {
	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func DeleteProject(ctx echo.Context) (err error) {
	var id = ctx.Param("id")

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()
	q := "select file_path from cv_project_dok where id_project = @P1"

	rows, err := db.Query(q, sql.Named("P1", id))

	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer rows.Close()

	var image []*string

	for rows.Next() {
		var filePath *string
		var err = rows.Scan(&filePath)

		if err != nil {
			defer panic(err.Error())
		}

		image = append(image, filePath)
	}

	err = rows.Err()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if len(image) > 0 {
		session := ctx.Get("session").(*session.Session)
		bucket := viper.GetString("aws.bucket")

		for _, img := range image {
			// DELETE FILE FROM S3
			svc := s3.New(session)

			_, err := svc.DeleteObject(&s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    img,
			})

			if err != nil {
				return err
			}

			err = svc.WaitUntilObjectNotExists(&s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    img,
			})

			if err != nil {
				return err
			}
		}
	}

	q = "delete from cv_project where id = @P1"

	_, err = db.Exec(q, sql.Named("P1", id))

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	q = "delete from cv_project_dok where id_project = @P1"

	_, err = db.Exec(q, sql.Named("P1", id))

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func DeleteImage(ctx echo.Context) (err error) {
	req := new(DeleteProjectImage)

	if err := ctx.Bind(req); err != nil {
		return err
	}

	if err := ctx.Validate(req); err != nil {
		return err
	}

	var id = req.ID
	var no = req.No
	var filePath *string

	var where = "and id_project = ''"
	if id != "" && len(id) > 0 {
		where = fmt.Sprintln("and id_project =", id)
	}

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	q := fmt.Sprintln("select file_path from cv_project_dok where no_urut = @P1", where)

	err = db.QueryRow(q, sql.Named("P1", no)).Scan(&filePath)

	if err != nil && err != sql.ErrNoRows {
		fmt.Println(err.Error())
		return
	}

	session := ctx.Get("session").(*session.Session)
	bucket := viper.GetString("aws.bucket")

	if filePath != nil {
		// DELETE FILE FROM S3
		svc := s3.New(session)

		_, err := svc.DeleteObject(&s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    filePath,
		})

		if err != nil {
			return err
		}

		err = svc.WaitUntilObjectNotExists(&s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    filePath,
		})

		if err != nil {
			return err
		}
	}

	q = fmt.Sprintln("delete from cv_project_dok where no_urut = @P1", where)

	_, err = db.Exec(q, sql.Named("P1", req.No))

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func UploadImageProject(ctx echo.Context) (err error) {
	var id = ctx.FormValue("id")
	var flag = ctx.FormValue("flag")
	var no = ctx.FormValue("no")
	var filePath *string

	var where = "and id_project = ''"
	if id != "" && len(id) > 0 {
		where = fmt.Sprintln("and id_project =", id)
	}

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	q := fmt.Sprintln("select file_path from cv_project_dok where no_urut = @P1", where)

	err = db.QueryRow(q, sql.Named("P1", no)).Scan(&filePath)
	var errRow = err

	if err != nil && err != sql.ErrNoRows {
		fmt.Println(err.Error())
		return
	}

	file, header, _ := ctx.Request().FormFile("file")
	defer file.Close()

	buff := bytes.NewBuffer(nil)

	_, err = io.Copy(buff, file)

	if err != nil {
		fmt.Println(err.Error())
	}

	check := CheckIsImage(buff.Bytes())

	if check == "" {
		res := &Response{
			Status:  false,
			Message: "File tidak valid",
		}

		return ctx.JSON(http.StatusInternalServerError, res)
	}

	session := ctx.Get("session").(*session.Session)
	uploader := s3manager.NewUploader(session)

	bucket := viper.GetString("aws.bucket")
	fileName := fmt.Sprintf("dev-%s", header.Filename)

	if filePath != nil {
		// DELETE FILE FROM S3
		svc := s3.New(session)

		_, err := svc.DeleteObject(&s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    filePath,
		})

		if err != nil {
			return err
		}

		err = svc.WaitUntilObjectNotExists(&s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    filePath,
		})

		if err != nil {
			return err
		}
	}

	//UPLOAD TO S3
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		ACL:    aws.String("bucket-owner-full-control"),
		Key:    aws.String(fileName),
		Body:   bytes.NewReader(buff.Bytes()),
	})

	if err != nil {
		return err
	}

	if errRow == sql.ErrNoRows {
		q = "insert into cv_project_dok (id_project, flag_thumb, file_path, no_urut) values (@P1, @P2, @P3, @P4)"
		_, err = db.Exec(q, sql.Named("P1", id), sql.Named("P2", flag), sql.Named("P3", fileName), sql.Named("P4", no))
	} else {
		q = fmt.Sprintln("update cv_project_dok set file_path = @P1 where no_urut = @P2", where)
		_, err = db.Exec(q, sql.Named("P1", fileName), sql.Named("P2", no))
	}

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func UpdateProject(ctx echo.Context) (err error) {
	req := new(DataProject)

	if err := ctx.Bind(req); err != nil {
		return err
	}

	if err := ctx.Validate(req); err != nil {
		return err
	}

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	q := "update cv_project  set nama = @P1, deskripsi = @P2, pic = @P3 where id = @P4"
	_, err = db.Exec(q, sql.Named("P1", req.Nama), sql.Named("P2", req.Deskripsi), sql.Named("P3", req.PIC), sql.Named("P4", req.ID))

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if len(req.Images) > 0 {
		q := "update cv_project_dok set id_project = @P1, flag_thumb = @P2 where id_project = '' and no_urut = @P3"
		for _, image := range req.Images {
			_, err = db.Exec(q, sql.Named("P1", req.ID), sql.Named("P2", image.Flag), sql.Named("P3", image.No))

			if err != nil {
				fmt.Println(err.Error())
				return
			}
		}
	}

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func StoreProject(ctx echo.Context) (err error) {
	req := new(DataProject)

	if err := ctx.Bind(req); err != nil {
		return err
	}

	if err := ctx.Validate(req); err != nil {
		return err
	}

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	id := GenerateProject()

	q := "insert into cv_project (id, nama, deskripsi, pic) values (@P1, @P2, @P3, @P4)"
	_, err = db.Exec(q, sql.Named("P1", id), sql.Named("P2", req.Nama), sql.Named("P3", req.Deskripsi), sql.Named("P4", req.PIC))

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if len(req.Images) > 0 {
		q := "update cv_project_dok set id_project = @P1, flag_thumb = @P2 where id_project = '' and no_urut = @P3"
		for _, image := range req.Images {
			_, err = db.Exec(q, sql.Named("P1", id), sql.Named("P2", image.Flag), sql.Named("P3", image.No))

			if err != nil {
				fmt.Println(err.Error())
				return
			}
		}
	}

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func IndexProject(ctx echo.Context) (err error) {
	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	q := "select id, nama, deskripsi, pic from cv_project order by id desc"

	rows, err := db.Query(q)

	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer rows.Close()

	var data []DataProject

	for rows.Next() {
		var each = DataProject{}
		var err = rows.Scan(&each.ID, &each.Nama, &each.Deskripsi, &each.PIC)

		if err != nil {
			defer panic(err.Error())
		}

		data = append(data, each)
	}

	err = rows.Err()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	res := &ResponseData{
		Status: true,
		Data:   data,
	}

	return ctx.JSON(http.StatusOK, res)

}

func ShowImage(ctx echo.Context) (err error) {
	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	bucket := viper.GetString("aws.bucket")

	data := ctx.Request().Context().Value("user").(jwt.MapClaims)
	var filePath *string

	q := `select foto
	from cv_user
	where nik = @P1`

	err = db.QueryRow(q, sql.Named("P1", data["nik"])).Scan(&filePath)

	if err != nil && err != sql.ErrNoRows {
		fmt.Println(err.Error())
		return
	}

	var file string
	if filePath != nil {
		file = "https://" + bucket + "." + "s3-" + AWS_REGION + ".amazonaws.com/" + *filePath
	}

	res := &ResponseData{
		Status: true,
		Data:   file,
	}

	return ctx.JSON(http.StatusOK, res)
}

func uploadImage(ctx echo.Context) (err error) {
	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	file, header, _ := ctx.Request().FormFile("file")
	defer file.Close()

	buff := bytes.NewBuffer(nil)

	_, err = io.Copy(buff, file)

	if err != nil {
		fmt.Println(err.Error())
	}

	check := CheckIsImage(buff.Bytes())

	if check == "" {
		res := &Response{
			Status:  false,
			Message: "File tidak valid",
		}

		return ctx.JSON(http.StatusInternalServerError, res)
	}

	session := ctx.Get("session").(*session.Session)
	uploader := s3manager.NewUploader(session)

	bucket := viper.GetString("aws.bucket")
	fileName := fmt.Sprintf("dev-%s", header.Filename)

	data := ctx.Request().Context().Value("user").(jwt.MapClaims)
	var filePath *string
	q := `select foto
	from cv_user
	where nik = @P1`

	err = db.QueryRow(q, sql.Named("P1", data["nik"])).Scan(&filePath)

	if err != nil && err != sql.ErrNoRows {
		fmt.Println(err.Error())
		return
	}

	if filePath != nil {
		// DELETE FILE FROM S3
		svc := s3.New(session)

		_, err := svc.DeleteObject(&s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    filePath,
		})

		if err != nil {
			return err
		}

		err = svc.WaitUntilObjectNotExists(&s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    filePath,
		})

		if err != nil {
			return err
		}
	}

	//UPLOAD TO S3
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		ACL:    aws.String("bucket-owner-full-control"),
		Key:    aws.String(fileName),
		Body:   bytes.NewReader(buff.Bytes()),
	})

	if err != nil {
		return err
	}

	q = `update cv_user set foto = @P1
	where nik = @P2`

	_, err = db.Exec(q, sql.Named("P1", fileName), data["nik"])

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func Update(ctx echo.Context) (err error) {
	req := new(DataUser)

	if err := ctx.Bind(req); err != nil {
		return err
	}

	if err := ctx.Validate(req); err != nil {
		return err
	}

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	data := ctx.Request().Context().Value("user").(jwt.MapClaims)

	q := `update cv_user set nama = @P1, jk = @P2, alamat = @P3, jabatan = @P4
	where nik = @P5`

	_, err = db.Exec(q, sql.Named("P1", req.Nama), sql.Named("P2", req.Jk), sql.Named("P3", req.Alamat), sql.Named("P4", req.Jabatan), data["nik"])

	if err != nil {
		fmt.Println(err.Error())
		return
	}
	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func Show(ctx echo.Context) (err error) {
	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	data := ctx.Request().Context().Value("user").(jwt.MapClaims)
	var user = DataUser{}

	q := `select nama, jk, alamat, jabatan
	from cv_user
	where nik = @P1`

	err = db.QueryRow(q, sql.Named("P1", data["nik"])).Scan(&user.Nama, &user.Jk, &user.Alamat, &user.Jabatan)

	if err != nil && err != sql.ErrNoRows {
		fmt.Println(err.Error())
		return
	}

	res := &ResponseData{
		Status: true,
		Data:   user,
	}

	return ctx.JSON(http.StatusOK, res)
}

func Logout(ctx echo.Context) (err error) {
	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.HttpOnly = true
	cookie.Value = ""
	cookie.Expires = time.Unix(0, 0)
	ctx.SetCookie(cookie)

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}

func Login(ctx echo.Context) (err error) {
	req := new(User)

	if err := ctx.Bind(req); err != nil {
		return err
	}

	if err := ctx.Validate(req); err != nil {
		return err
	}

	// CONNECT KE DB
	db, err := config.Connect()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer db.Close()

	var user = User{}

	q := `select nik, password
	from cv_user
	where nik = @P1`

	err = db.QueryRow(q, sql.Named("P1", req.Nik)).Scan(&user.Nik, &user.Password)

	if err != nil && err != sql.ErrNoRows {
		fmt.Println(err.Error())
		return
	}

	if err == sql.ErrNoRows {
		res := &Response{
			Status:  false,
			Message: "NIK tidak terdaftar",
		}
		return ctx.JSON(http.StatusInternalServerError, res)
	}

	check := CheckPasswordHash(req.Password, user.Password)

	if !check {
		res := &Response{
			Status:  false,
			Message: "Password salah",
		}
		return ctx.JSON(http.StatusInternalServerError, res)
	}

	claims := &jwtCustomClaims{
		Nik: user.Nik,
		StandardClaims: jwt.StandardClaims{
			Issuer:    viper.GetString("appName"),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	token := jwt.NewWithClaims(JWT_SIGNING_METHOD, claims)

	_token, err := token.SignedString([]byte(viper.GetString("appKey.key")))

	if err != nil {
		fmt.Println(err)
		return
	}

	cookie := new(http.Cookie)
	cookie.Name = "access-token"
	cookie.HttpOnly = true
	cookie.Value = _token
	cookie.Expires = time.Now().Add(time.Hour * 2)
	ctx.SetCookie(cookie)

	res := &Response{
		Status:  true,
		Message: "OK",
	}

	return ctx.JSON(http.StatusOK, res)
}
