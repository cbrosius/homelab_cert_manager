package main

import (
	"log"

	"github.com/spf13/viper"
)

// debugLog logs debug messages only when debug mode is enabled
func debugLog(format string, v ...interface{}) {
	if viper.GetBool("debug") {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// initLoggingDefaults sets default values for logging configuration
func initLoggingDefaults() {
	viper.SetDefault("debug", false)
}
