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

type IPRLogger struct {
	*log.Logger
}

func NewLogger() *IPRLogger {
	return &IPRLogger{
		log.New(os.Stdout, "iprd: ", log.LstdFlags),
	}
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

func (l *IPRLogger) SetPrefix(prefix string) {
	l.SetPrefix(prefix)
}

func (l *IPRLogger) Info(raw string) {
	if msg, ok := sanitizeMessage(raw); ok {
		l.Printf(infoColor, msg)
	}
}

func (l *IPRLogger) Debug(msg string) {
	l.Printf(debugColor, msg)
}

func (l *IPRLogger) Error(err error) {
	l.Printf(errorColor, err)
}

func (l *IPRLogger) Panic(err error) {
	l.Panicf(errorColor, err)
}
