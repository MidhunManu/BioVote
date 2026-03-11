package main

import (
	"context"
	"log"
	"os"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

// Client wraps Firebase services
type Client struct {
	Firestore *firestore.Client
	Auth      *auth.Client
}

var instance *Client

// Init initializes Firebase app and returns a Client
func Init(ctx context.Context) *Client {
	if instance != nil {
		return instance
	}

	credFile := os.Getenv("FIREBASE_CREDENTIALS_FILE")
	projectID := os.Getenv("FIREBASE_PROJECT_ID")

	var app *firebase.App
	var err error

	if credFile != "" {
		// Production: use service account key file
		opt := option.WithCredentialsFile(credFile)
		conf := &firebase.Config{ProjectID: projectID}
		app, err = firebase.NewApp(ctx, conf, opt)
	} else {
		// Development: use Application Default Credentials
		conf := &firebase.Config{ProjectID: projectID}
		app, err = firebase.NewApp(ctx, conf)
	}

	if err != nil {
		log.Fatalf("❌ Firebase init failed: %v", err)
	}

	fsClient, err := app.Firestore(ctx)
	if err != nil {
		log.Fatalf("❌ Firestore init failed: %v", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("❌ Firebase Auth init failed: %v", err)
	}

	instance = &Client{
		Firestore: fsClient,
		Auth:      authClient,
	}

	log.Println("✅ Firebase connected — Project:", projectID)
	return instance
}

// Get returns the singleton Firebase client
func Get() *Client {
	if instance == nil {
		log.Fatal("Firebase not initialized. Call firebase.Init() first.")
	}
	return instance
}
