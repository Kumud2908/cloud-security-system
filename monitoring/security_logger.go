package monitoring

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type SecurityEvent struct {
	Type      string    `bson:"type"`
	User      string    `bson:"user"`
	IP        string    `bson:"ip"`
	Timestamp time.Time `bson:"timestamp"`
}

type SecurityLogger struct {
	Collection *mongo.Collection
	Ctx        context.Context
}

func NewSecurityLogger(collection *mongo.Collection, ctx context.Context) *SecurityLogger {
	return &SecurityLogger{
		Collection: collection,
		Ctx:        ctx,
	}
}

func (s *SecurityLogger) LogEvent(eventType string, user string, ip string) {
	event := SecurityEvent{
		Type:      eventType,
		User:      user,
		IP:        ip,
		Timestamp: time.Now(),
	}

	_, err := s.Collection.InsertOne(s.Ctx, event)
	if err != nil {
		log.Println("Failed to insert security event:", err)
	}
}
