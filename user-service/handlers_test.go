package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"users-service/database"
)

func TestSignUpHandler(t *testing.T) {
	_ = godotenv.Load()
	dbUrl := os.Getenv("TEST_DATABASE_URL")
	app, err := newApp(dbUrl, "", "")
	require.NoError(t, err, "could not create app instance")

	t.Cleanup(func() {
		cleanupDB(t, app.dbPool)
	})

	type testCase struct {
		name         string
		form         url.Values
		expectedCode int
		expectUser   bool
	}

	tests := []testCase{
		{
			name: "valid signup 1",
			form: url.Values{
				"phone_number": []string{"+201110743419"},
				"password":     []string{"password"},
				"user_type":    []string{"center"},
				"first_name":   []string{"Mohamed"},
				"middle_name":  []string{"Ahmed"},
				"last_name":    []string{"Elhawawshy"},
			},
			expectedCode: http.StatusCreated,
			expectUser:   true,
		},
		{
			name: "valid signup 2",
			form: url.Values{
				"phone_number":        []string{"+201110743418"},
				"password":            []string{"password"},
				"user_type":           []string{"student"},
				"parent_phone_number": []string{"+201110743416"},
				"first_name":          []string{"Mohamed"},
				"middle_name":         []string{"Ahmed"},
				"last_name":           []string{"Elhawawshy"},
			},
			expectedCode: http.StatusCreated,
			expectUser:   true,
		},
		{
			name: "duplicated user",
			form: url.Values{
				"phone_number": []string{"+201110743419"},
				"password":     []string{"password"},
				"user_type":    []string{"center"},
				"first_name":   []string{"Mohamed"},
				"middle_name":  []string{"Ahmed"},
				"last_name":    []string{"Elhawawshy"},
			},
			expectedCode: http.StatusConflict,
			expectUser:   false,
		},
		{
			name: "missing phone number",
			form: url.Values{
				"password":    []string{"password"},
				"user_type":   []string{"center"},
				"first_name":  []string{"Mohamed"},
				"middle_name": []string{"Ahmed"},
				"last_name":   []string{"Elhawawshy"},
			},
			expectedCode: http.StatusBadRequest,
			expectUser:   false,
		},
		{
			name: "invalid phone number format",
			form: url.Values{
				"phone_number": []string{"invalid_number"},
				"password":     []string{"password"},
				"user_type":    []string{"center"},
				"first_name":   []string{"Mohamed"},
				"middle_name":  []string{"Ahmed"},
				"last_name":    []string{"Elhawawshy"},
			},
			expectedCode: http.StatusBadRequest,
			expectUser:   false,
		},
		{
			name: "missing password",
			form: url.Values{
				"phone_number": []string{"+201110743419"},
				"user_type":    []string{"center"},
				"first_name":   []string{"Mohamed"},
				"middle_name":  []string{"Ahmed"},
				"last_name":    []string{"Elhawawshy"},
			},
			expectedCode: http.StatusBadRequest,
			expectUser:   false,
		},
		{
			name: "missing user type",
			form: url.Values{
				"phone_number": []string{"+201110743419"},
				"password":     []string{"password"},
				"first_name":   []string{"Mohamed"},
				"middle_name":  []string{"Ahmed"},
				"last_name":    []string{"Elhawawshy"},
			},
			expectedCode: http.StatusBadRequest,
			expectUser:   false,
		},
		{
			name: "missing parent phone number",
			form: url.Values{
				"phone_number": []string{"+201110743419"},
				"password":     []string{"password"},
				"user_type":    []string{"student"},
				"first_name":   []string{"Mohamed"},
				"middle_name":  []string{"Ahmed"},
				"last_name":    []string{"Elhawawshy"},
			},
			expectedCode: http.StatusBadRequest,
			expectUser:   false,
		},
	}

	e := echo.New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.form.Encode()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath("/auth/signup")

			err := app.signUpHandler(c)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			if tt.expectUser {
				var s struct {
					UserID string `json:"user_id"`
				}
				assert.NoError(t, json.NewDecoder(rec.Body).Decode(&s))

				db, err := app.dbPool.Acquire(context.Background())
				require.NoError(t, err)
				defer db.Release()

				q := database.New(db)
				id, err := uuid.Parse(s.UserID)
				require.NoError(t, err)

				user, err := q.GetUser(context.Background(), id)
				require.NoError(t, err)

				assert.Equal(t, s.UserID, user.UserID.String())
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	_ = godotenv.Load()
	dbUrl := os.Getenv("TEST_DATABASE_URL")
	app, err := newApp(dbUrl, "", "")
	require.NoError(t, err, "could not create app instance")

	t.Cleanup(func() {
		cleanupDB(t, app.dbPool)
	})

	// Setup: Create a user to log in with
	userID := uuid.New()
	phoneNumber := "+201110743419"
	password := "password"
	hashedPassword := hashPassword(password)

	conn, err := app.dbPool.Acquire(context.Background())
	require.NoError(t, err)
	defer conn.Release()

	q := database.New(conn)
	_, err = q.CreateUser(context.Background(), database.CreateUserParams{
		UserID:       userID,
		PasswordHash: hashedPassword,
		UserType:     "center",
	})
	require.NoError(t, err)
	_, err = q.CreatePhone(context.Background(), database.CreatePhoneParams{
		PhoneNumber: phoneNumber,
		UserID:      toPgUUID(userID),
	})
	require.NoError(t, err)

	type testCase struct {
		name         string
		form         url.Values
		expectedCode int
		expectTokens bool
	}

	tests := []testCase{
		{
			name: "valid login",
			form: url.Values{
				"phone_number": []string{phoneNumber},
				"password":     []string{password},
			},
			expectedCode: http.StatusOK,
			expectTokens: true,
		},
		{
			name: "invalid password",
			form: url.Values{
				"phone_number": []string{phoneNumber},
				"password":     []string{"wrongpassword"},
			},
			expectedCode: http.StatusUnauthorized,
			expectTokens: false,
		},
		{
			name: "non-existent user",
			form: url.Values{
				"phone_number": []string{"+201000000000"},
				"password":     []string{password},
			},
			expectedCode: http.StatusUnauthorized,
			expectTokens: false,
		},
	}

	e := echo.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.form.Encode()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath("/auth/login")

			err := app.loginHandler(c)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedCode, rec.Code)

			if tt.expectTokens {
				var tokens struct {
					AccessToken  string `json:"access_token"`
					RefreshToken string `json:"refresh_token"`
				}
				assert.NoError(t, json.NewDecoder(rec.Body).Decode(&tokens))
				assert.NotEmpty(t, tokens.AccessToken)
				assert.NotEmpty(t, tokens.RefreshToken)

				cookie := rec.Result().Cookies()[0]
				assert.Equal(t, "refresh_token", cookie.Name)
				assert.NotEmpty(t, cookie.Value)
			}
		})
	}
}

func TestLogoutHandler(t *testing.T) {
	app := &Application{}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/user/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := app.logoutHandler(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRefreshTokenHandler(t *testing.T) {
	_ = godotenv.Load()
	dbUrl := os.Getenv("TEST_DATABASE_URL")

	app, err := newApp(dbUrl, "", "")
	require.NoError(t, err, "could not create app instance")

	t.Cleanup(func() {
		cleanupDB(t, app.dbPool)
	})

	userID := uuid.NewString()
	userType := "center"

	e := echo.New()

	t.Run("valid refresh token", func(t *testing.T) {
		refreshToken, err := createToken(userType, userID, time.Now().Add(time.Hour))
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/user/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: refreshToken,
		})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = app.refreshToken(c)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, rec.Code)

		var token struct {
			AccessToken string `json:"access_token"`
		}
		assert.NoError(t, json.NewDecoder(rec.Body).Decode(&token))
		assert.NotEmpty(t, token.AccessToken)

		cookie := rec.Result().Cookies()[0]
		assert.Equal(t, "refresh_token", cookie.Name)
		assert.NotEmpty(t, cookie.Value)
		assert.NotEqual(t, refreshToken, cookie.Value)
	})

	t.Run("no refresh token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = app.refreshToken(c)
		require.NoError(t, err)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: "invalidtoken",
		})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = app.refreshToken(c)
		require.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
