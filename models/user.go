package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID            primitive.ObjectID `json:"id" bson:"_id"`
	Username      string             `json:"username" bson:"username"`
	Password      string             `json:"password" bson:"password"`
	Role          string             `json:"role" bson:"role"`
	AccountLocked bool               `json:"account_locked" bson:"account_locked"`
	CreatedAt     time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at" bson:"updated_at"`
}
