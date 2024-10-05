package main

import (
	"github.com/brianxor/tls-api/server"
	"github.com/joho/godotenv"
	"golang.org/x/sys/windows"
	"log"
	"os"
)

// Copied from https://github.com/fatih/color/blob/main/color_windows.go
func init() {
	// Opt-in for ansi color support for current process.
	// https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#output-sequences
	var outMode uint32
	out := windows.Handle(os.Stdout.Fd())
	if err := windows.GetConsoleMode(out, &outMode); err != nil {
		return
	}
	outMode |= windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	_ = windows.SetConsoleMode(out, outMode)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	serverHost := os.Getenv("SERVER_HOST")

	if serverHost == "" {
		log.Fatal("SERVER_HOST not set, please check your env file!")
	}

	serverPort := os.Getenv("SERVER_PORT")

	if serverPort == "" {
		log.Fatal("SERVER_PORT not set, please check your env file!")
	}

	if err := server.StartServer(serverHost, serverPort); err != nil {
		log.Fatal(err)
	}
}
