// logger.go contains a getter to a singleton golang built-in logger instance.

package util

import (
	"log"
	"os"
	"sync"
)

// log.Logger can be replaced with a custom logger
var loggerInstance *log.Logger
var once sync.Once

func GetLogger() *log.Logger {
	once.Do(func() {
		// TODO: also log to file
		loggerInstance = log.New(os.Stdout, "", log.LstdFlags | log.Lshortfile)
	})
	return loggerInstance
}
