package server

import (
	"fmt"
	"github.com/brianxor/tls-api/server/handlers"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
)

func StartServer(serverHost string, serverPort string) error {
	app := fiber.New(fiber.Config{
		AppName: "TlsApi",
	})

	tlsGroup := app.Group("/tls")

	tlsGroup.Use(logger.New())
	tlsGroup.Use(recover.New())

	tlsGroup.Post("/forward", handlers.HandleTlsForwardRoute)

	serverAddress := fmt.Sprintf("%s:%s", serverHost, serverPort)

	if err := app.Listen(serverAddress); err != nil {
		return err
	}

	return nil
}
