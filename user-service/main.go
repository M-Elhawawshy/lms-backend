package main

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/segmentio/kafka-go"
	"log"
	"log/slog"
	"os"
)

type Application struct {
	logger      *slog.Logger
	dbPool      *pgxpool.Pool
	kafkaWriter *kafka.Writer
	kafkaReader *kafka.Reader
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("could not load env")
		return
	}
	dbUrl := os.Getenv("DATABASE_URL")
	app, err := newApp(dbUrl)
	if err != nil {
		log.Fatal("could not create app struct")
		return
	}

	e := echo.New()
	app.routes(e)
	fetcher := app.fetchEvents(context.Background())
	app.publishEvents(context.Background(), fetcher)
	e.Logger.Fatal(e.Start(os.Getenv("HOST_URL")))
}

func newApp(databaseUrl string) (*Application, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}))

	pool, err := openDB(databaseUrl)
	if err != nil {
		logger.Error("Could not open db")
		return nil, err
	}

	writer := newKafkaWriter()

	app := Application{
		logger:      logger,
		dbPool:      pool,
		kafkaWriter: writer,
		kafkaReader: nil,
	}

	return &app, nil
}
