package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
	"users-service/database"
)

var validate = validator.New()

type UserSerializer struct {
	UserID      uuid.UUID `json:"user_id"`
	PhoneNumber string    `json:"phone_number"`
	UserType    string    `json:"user_type"`
	FirstName   string    `json:"first_name"`
	MiddleName  string    `json:"middle_name"`
	LastName    string    `json:"last_name"`
}

type UserSignUpResponseSerializer struct {
	UserID       uuid.UUID `json:"user_id"`
	PhoneNumber  string    `json:"phone_number"`
	UserType     string    `json:"user_type"`
	FirstName    string    `json:"first_name"`
	MiddleName   string    `json:"middle_name"`
	LastName     string    `json:"last_name"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
}

type SignUpForm struct {
	PhoneNumber       string `form:"phone_number" validate:"required,e164"`
	ParentPhoneNumber string `form:"parent_phone_number" validate:"omitempty,e164"`
	Password          string `form:"password" validate:"required,min=8"`
	UserType          string `form:"user_type" validate:"required,oneof=center student teacher assistant"`
	FirstName         string `form:"first_name" validate:"required,alpha"`
	MiddleName        string `form:"middle_name" validate:"required,alpha"`
	LastName          string `form:"last_name" validate:"required,alpha"`
}

// todo: make the user logged in when they first signup
func (app *Application) signUpHandler(c echo.Context) error {
	var form SignUpForm
	if err := c.Bind(&form); err != nil {
		app.logger.Error("binding error", "error", err.Error())
		return app.badRequest(c, http.StatusText(http.StatusBadRequest), err)
	}
	if err := validate.Struct(form); err != nil {
		app.logger.Error("validation error", "error", err.Error())
		return app.validationError(c, err)
	}
	if form.UserType == STUDENT {
		if form.ParentPhoneNumber == "" {
			return app.badRequest(c, http.StatusText(http.StatusBadRequest), fmt.Errorf("missing parent_phone_number attribute"))
		}
		if err := validate.Var(form.ParentPhoneNumber, "e164"); err != nil {
			return app.badRequest(c, http.StatusText(http.StatusBadRequest), err)
		}
	}

	ctx := c.Request().Context()

	conn, err := app.dbPool.Acquire(ctx)
	if err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}
	defer tx.Rollback(ctx)

	q := database.New(tx)
	exists, err := q.PhoneExists(ctx, form.PhoneNumber)
	if exists {
		return c.JSON(http.StatusConflict, ErrorMessage{
			Message: "Duplicated phone number",
			Details: map[string]string{"Error": "This phone number already exists."},
		})
	}
	userID := uuid.New()
	user, err := q.CreateUser(ctx, database.CreateUserParams{
		UserID:       userID,
		PasswordHash: hashPassword(form.Password),
		UserType:     form.UserType,
	})
	if err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}

	if _, err := q.CreatePhone(ctx, database.CreatePhoneParams{
		PhoneNumber: form.PhoneNumber,
		UserID:      toPgUUID(user.UserID),
	}); err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}

	name, err := q.CreateName(ctx, database.CreateNameParams{
		UserID:     user.UserID,
		FirstName:  form.FirstName,
		MiddleName: form.MiddleName,
		LastName:   form.LastName,
	})
	if err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}

	switch user.UserType {
	case CENTER:
		_, err := q.CreateEmptyCenter(ctx, user.UserID)
		if err != nil {
			app.logger.Error("Database Error", "error", err.Error())
			return app.internalServerError(c, err)
		}
	case STUDENT:
		_, err := q.CreateStudent(ctx, database.CreateStudentParams{
			StudentID:   user.UserID,
			ParentPhone: form.ParentPhoneNumber,
		})
		if err != nil {
			app.logger.Error("Database Error", "error", err.Error())
			return app.internalServerError(c, err)
		}
	case TEACHER:
		educator, err := q.CreateEducator(ctx, database.CreateEducatorParams{
			EducatorID:   user.UserID,
			EducatorType: TEACHER,
		})
		if err != nil {
			app.logger.Error("Database Error", "error", err.Error())
			return app.internalServerError(c, err)
		}
		_, err = q.CreateTeacher(ctx, educator.EducatorID)
		if err != nil {
			app.logger.Error("Database Error", "error", err.Error())
			return app.internalServerError(c, err)
		}
	case ASSISTANT:
		educator, err := q.CreateEducator(ctx, database.CreateEducatorParams{
			EducatorID:   user.UserID,
			EducatorType: TEACHER,
		})
		if err != nil {
			app.logger.Error("Database Error", "error", err.Error())
			return app.internalServerError(c, err)
		}
		_, err = q.CreateAssistant(ctx, educator.EducatorID)
		if err != nil {
			app.logger.Error("Database Error", "error", err.Error())
			return app.internalServerError(c, err)
		}
	}

	userPayload := UserSerializer{
		UserID:      user.UserID,
		PhoneNumber: form.PhoneNumber,
		UserType:    user.UserType,
		FirstName:   name.FirstName,
		MiddleName:  name.MiddleName,
		LastName:    name.LastName,
	}

	payload, err := json.Marshal(userPayload)
	if err != nil {
		app.logger.Error("serializer error", "error", err.Error())
		return app.internalServerError(c, err)
	}

	_, err = q.InsertEvent(ctx, database.InsertEventParams{
		ID:            uuid.New(),
		EventType:     TOPIC_USER_CREATED,
		AggregateType: "user",
		AggregateID:   user.UserID.String(),
		Payload:       payload,
	})
	if err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}

	if err := tx.Commit(ctx); err != nil {
		app.logger.Error("Database error", "error", err.Error())
		return app.internalServerError(c, err)
	}

	accessToken, err := createToken(user.UserType, user.UserID.String(), time.Now().Add(time.Minute*15))
	if err != nil {
		return app.internalServerError(c, err)
	}

	expiration := time.Now().Add(time.Hour * 24 * 7)
	refreshToken, err := createToken(user.UserType, user.UserID.String(), expiration)

	serializer := UserSignUpResponseSerializer{
		UserID:       userPayload.UserID,
		PhoneNumber:  userPayload.PhoneNumber,
		UserType:     userPayload.UserType,
		FirstName:    userPayload.FirstName,
		MiddleName:   userPayload.MiddleName,
		LastName:     userPayload.LastName,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return c.JSON(http.StatusCreated, serializer)
}

type LoginForm struct {
	PhoneNumber string `form:"phone_number" validate:"required"`
	Password    string `form:"password" validate:"required"`
}

func (app *Application) loginHandler(c echo.Context) error {
	var form LoginForm
	err := c.Bind(&form)
	if err != nil {
		return app.internalServerError(c, err)
	}

	ctx := c.Request().Context()
	conn, err := app.dbPool.Acquire(ctx)
	if err != nil {
		return app.internalServerError(c, err)
	}
	defer conn.Release()
	q := database.New(conn)

	pgid, err := q.GetUserIDByPhone(ctx, form.PhoneNumber)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(http.StatusUnauthorized, ErrorMessage{
				Message: "Unauthorized",
				Details: map[string]string{"Error": "phone_number or password are incorrect"},
			})
		}
		return app.internalServerError(c, err)
	}
	idBytes := pgid.Bytes[:]
	userID, err := uuid.FromBytes(idBytes)
	if err != nil {
		return app.internalServerError(c, err)
	}
	user, err := q.GetUser(ctx, userID)
	if err != nil {
		return app.internalServerError(c, err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(form.Password))
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorMessage{
			Message: "Unauthorized",
			Details: map[string]string{"Error": "phone_number or password are incorrect"},
		})
	}

	accessToken, err := createToken(user.UserType, user.UserID.String(), time.Now().Add(time.Minute*15))
	if err != nil {
		return app.internalServerError(c, err)
	}

	expiration := time.Now().Add(time.Hour * 24 * 7)
	refreshToken, err := createToken(user.UserType, user.UserID.String(), expiration)
	if err != nil {
		return app.internalServerError(c, err)
	}
	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  expiration,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	type Tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	token := Tokens{accessToken, refreshToken}

	if err = c.JSON(http.StatusOK, token); err != nil {
		c.SetCookie(&http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		return app.internalServerError(c, err)
	}

	return err
}

func (app *Application) logoutHandler(c echo.Context) error {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		cookie = &http.Cookie{}
	}
	var refreshToken = cookie.Value
	type RequestRefreshToken struct {
		RefreshToken string `json:"refresh_token" form:"refresh_token"`
	}
	if refreshToken == "" {
		var requestRefreshToken RequestRefreshToken
		err = c.Bind(&requestRefreshToken)
		if err != nil {
			return app.internalServerError(c, err)
		}
		refreshToken = requestRefreshToken.RefreshToken
	}
	if refreshToken == "" {
		return app.badRequest(c,
			"No refresh_token provided",
			fmt.Errorf("no refresh_token in cookie or body"),
		)
	}
	refreshTokenVerified, err := verifyToken(refreshToken)
	if err != nil {
		return app.badRequest(c, "invalid refresh_token", fmt.Errorf("invalid refresh_token found"))
	}

	claims := refreshTokenVerified.Claims.(*jwtCustomClaims)
	jtiString := claims.ID
	userIDString := claims.Subject
	expiresAt := claims.ExpiresAt

	jti, err := uuid.Parse(jtiString)
	if err != nil {
		return app.internalServerError(c, err)
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return app.internalServerError(c, err)
	}

	conn, err := app.dbPool.Acquire(c.Request().Context())
	if err != nil {
		return app.internalServerError(c, err)
	}
	q := database.New(conn)
	isRevoked, err := q.IsTokenRevoked(c.Request().Context(), jti)
	if err != nil {
		return app.internalServerError(c, err)
	}
	if isRevoked {
		return app.badRequest(c, "token already revoked", fmt.Errorf("refresh_token is already revoked"))
	}
	_, err = q.RevokeJwt(c.Request().Context(), database.RevokeJwtParams{
		Jti:       jti,
		UserID:    userID,
		ExpiresAt: expiresAt.Time,
	})
	if err != nil {
		return app.internalServerError(c, err)
	}

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "logout successful"})
}

func (app *Application) refreshToken(c echo.Context) error {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		cookie = &http.Cookie{}
	}
	var refreshToken = cookie.Value
	type RequestRefreshToken struct {
		RefreshToken string `json:"refresh_token" form:"refresh_token"`
	}
	if refreshToken == "" {
		var requestRefreshToken RequestRefreshToken
		err := c.Bind(&requestRefreshToken)
		if err != nil {
			return app.internalServerError(c, err)
		}
		refreshToken = requestRefreshToken.RefreshToken
	}
	if refreshToken == "" {
		return app.badRequest(c,
			"No refresh_token provided",
			fmt.Errorf("no refresh_token in cookie or body"),
		)
	}

	token, err := verifyToken(refreshToken)
	if err != nil || !token.Valid {
		return c.JSON(http.StatusUnauthorized, ErrorMessage{Message: "Invalid refresh token"})
	}

	claims, ok := token.Claims.(*jwtCustomClaims)
	if !ok {
		return c.JSON(http.StatusUnauthorized, ErrorMessage{Message: "Invalid token claims"})
	}

	newAccessToken, err := createToken(claims.UserType, claims.Subject, time.Now().Add(time.Minute*15))
	if err != nil {
		return app.internalServerError(c, err)
	}

	newRefreshToken, err := createToken(claims.UserType, claims.Subject, time.Now().Add(time.Hour*24*7))
	if err != nil {
		return app.internalServerError(c, err)
	}

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Expires:  time.Now().Add(time.Hour * 24 * 7),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	type Tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	tokensResponse := Tokens{newAccessToken, newRefreshToken}

	return c.JSON(http.StatusOK, tokensResponse)
}
