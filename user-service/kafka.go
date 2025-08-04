package main

import (
	"context"
	"crypto/tls"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"time"
	"users-service/database"
)

func newKafkaWriter(kafkaURL, connectionString string) *kafka.Writer {
	mechanism := plain.Mechanism{
		Username: "$ConnectionString",
		Password: connectionString,
	}
	transport := &kafka.Transport{
		SASL: mechanism,
		TLS:  &tls.Config{},
	}

	return &kafka.Writer{
		Addr:                   kafka.TCP(kafkaURL),
		Balancer:               &kafka.LeastBytes{},
		ReadTimeout:            10 * time.Second,
		WriteTimeout:           10 * time.Second,
		Transport:              transport,
		AllowAutoTopicCreation: true,
	}
}

// todo: add retry logic
func (app *Application) fetchEvents(ctx context.Context) <-chan database.Outbox {
	outChan := make(chan database.Outbox, 100)

	go func() {
		defer close(outChan)

		// Dedicated listener connection
		listenConn, err := app.dbPool.Acquire(ctx)
		if err != nil {
			app.logger.Error("Could not acquire listen conn", "err", err)
			return
		}
		defer listenConn.Release()

		_, err = listenConn.Exec(ctx, "LISTEN outbox_channel")
		if err != nil {
			app.logger.Error("LISTEN failed", "err", err)
			return
		}

		for {
			if ctx.Err() != nil {
				return
			}

			notification, err := listenConn.Conn().WaitForNotification(ctx)
			if err != nil {
				if ctx.Err() != nil {
					app.logger.Info("Context canceled, stopping listener")
					return
				}
				app.logger.Error("WaitForNotification failed", "err", err)
				break
			}

			if notification.Channel != "outbox_channel" {
				break
			}

			// Fetch events using a separate query connection
			queryConn, err := app.dbPool.Acquire(ctx)
			if err != nil {
				app.logger.Error("Could not acquire query conn", "err", err)
				continue
			}

			q := database.New(queryConn)
			events, err := q.GetUnpublishedEvents(ctx)
			queryConn.Release()

			if err != nil {
				app.logger.Error("Failed to fetch events", "err", err)
				continue
			}

			for _, event := range events {
				select {
				case outChan <- event:
					app.logger.Info("Event fetched and sent to channel")
				case <-ctx.Done():
					app.logger.Info("Context canceled during send")
					return
				}
			}
		}
	}()

	return outChan
}

func (app *Application) publishEvents(ctx context.Context, eventsChan <-chan database.Outbox) {
	go func() {
		for {
			select {

			case event, ok := <-eventsChan:
				if !ok {
					return // channel closed
				}

				err := app.kafkaWriter.WriteMessages(ctx, kafka.Message{
					Topic: event.EventType,
					Key:   []byte(event.AggregateID),
					Value: event.Payload,
				})
				if err != nil {
					app.logger.Error("Failed to write the event into Kafka", "event_id", event.ID, "err", err)
					continue
				}
				app.logger.Info("Event was published into kafka successfully")

				// Update DB to mark event as published
				DBConn, err := app.dbPool.Acquire(ctx)
				if err != nil {
					app.logger.Error("Could not acquire DB connection", "err", err)
					continue
				}

				q := database.New(DBConn)
				err = q.SetEventAsPublished(ctx, event.ID)
				DBConn.Release()
				if err != nil {
					app.logger.Error("Could not mark event as published", "event_id", event.ID, "err", err)
				}
			}
		}
	}()
}
