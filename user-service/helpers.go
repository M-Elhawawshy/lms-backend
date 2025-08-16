package main

import (
	"context"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"testing"
)

func openDB(dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, err
	}
	err = pool.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	return pool, nil
}

func (app *Application) badRequest(c echo.Context, msg string, err error) error {
	return c.JSON(http.StatusBadRequest, ErrorMessage{
		Message: msg,
		Details: map[string]string{"error": err.Error()},
	})
}

func (app *Application) internalServerError(c echo.Context, err error) error {
	return c.JSON(http.StatusInternalServerError, ErrorMessage{
		Message: "Internal Server Error",
		Details: map[string]string{"error": err.Error()},
	})
}

func (app *Application) validationError(c echo.Context, valErr error) error {
	errors := map[string]string{}
	for _, err := range valErr.(validator.ValidationErrors) {
		errors[err.Field()] = err.Error()
	}
	return c.JSON(http.StatusBadRequest, ErrorMessage{
		Message: "Validation Error",
		Details: errors,
	})
}

func hashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), PASSWORD_COST)
	return string(hash)
}

func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func cleanupDB(t *testing.T, db *pgxpool.Pool) {
	t.Helper()

	_, err := db.Exec(context.Background(), `
		DO $$
		DECLARE
			r RECORD;
		BEGIN
			FOR r IN (
				SELECT tablename 
				FROM pg_tables 
				WHERE schemaname = 'public'
			) LOOP
				EXECUTE 'TRUNCATE TABLE public.' || quote_ident(r.tablename) || ' RESTART IDENTITY CASCADE';
			END LOOP;
		END $$;
	`)
	require.NoError(t, err)
}
