package main

import (
	"flag"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"gopkg.in/natefinch/lumberjack.v2"
)

var debug = flag.Bool("d", false, "debug")

func initLog() {
	zerolog.MessageFieldName = "msg"
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(level)

	writers := []io.Writer{}

	if *debug {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.DateTime})
		zerolog.SetGlobalLevel(0)
		log.Logger = log.With().Caller().Logger()
	}

	if logFile != "" {
		writers = append(writers, &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    logMaxSize, // megabytes
			MaxBackups: logMaxBackups,
			MaxAge:     logMaxAge, // days
			Compress:   true,
		})
	}

	if len(writers) > 0 {
		log.Logger = log.Output(zerolog.MultiLevelWriter(writers...))
	}

        hostname, _ := os.Hostname()
	log.Logger = log.With().
		Str("hostname", hostname).
		Int("pid", os.Getpid()).
		Logger()
}
