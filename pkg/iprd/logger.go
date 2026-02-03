package iprd

import (
	"log"
	"os"
)

const (
	debugColor = "\033[0;36m%s\033[0m"
	infoColor  = "\033[1;33m%s\033[0m"
	errorColor = "\033[1;31m%s\033[0m"
)

type iprdLogger struct {
	*log.Logger
}

func NewIPRDLogger() *iprdLogger {
	return &iprdLogger{
		log.New(os.Stdout, "iprd: ", log.LstdFlags),
	}
}

func (l *iprdLogger) Debug(msg string) {
	l.Printf(debugColor, msg)
}

func (l *iprdLogger) Info(raw string) {
	if msg, ok := sanitizeMessage(raw); ok {
		l.Printf(infoColor, msg)
	}
}

func (l *iprdLogger) Error(err error) {
	l.Printf(errorColor, err)
}

func (l *iprdLogger) Panic(err error) {
	l.Panicf(errorColor, err)
}

func sanitizeMessage(msg string) (string, bool) {
	if len := len(msg); len == 0 {
		return "", false
	} else {
		if msg[len-1] == '\n' {
			msg = msg[:len-1]
		}

		return msg, true
	}
}
