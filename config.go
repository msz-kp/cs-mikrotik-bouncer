package main

import (
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

var (
	logLevel              string
	logFile               string
	logMaxSize            int
	logMaxBackups         int
	logMaxAge             int
	crowdsecBouncerAPIKey string
	crowdsecBouncerURL    string
	mikrotikHost          string
	username              string
	password              string
	async                 bool
	useTLS                bool
	useIPV6               bool
	crowdsecOrigins       []string
)

func initConfig() {
	viper.SetConfigName("crowdsec-mikrotik-bouncer")
	viper.AddConfigPath("/etc/crowdsec/bouncers")
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("ReadInConfig failed")
	}

	viper.BindEnv("log_level")
	viper.SetDefault("log_level", 1)
	viper.BindEnv("log_file")
	viper.BindEnv("log_max_size")
	viper.SetDefault("log_max_size", 1)
	viper.BindEnv("log_max_backups")
	viper.SetDefault("log_max_backups", 4)
	viper.BindEnv("log_max_age")
	viper.SetDefault("log_max_age", 30)
	viper.BindEnv("crowdsec_bouncer_api_key")
	viper.BindEnv("crowdsec_url")
	viper.SetDefault("crowdsec_url", "http://127.0.0.1:8080/")
	viper.BindEnv("mikrotik_host")
	viper.BindEnv("mikrotik_user")
	viper.BindEnv("mikrotik_pass")
	viper.BindEnv("mikrotik_tls")
	viper.SetDefault("mikrotik_tls", "true")
	viper.BindEnv("mikrotik_ipv6")
	viper.SetDefault("mikrotik_ipv6", "true")
	viper.BindEnv("crowdsec_origins")
	viper.SetDefault("crowdsec_origins", nil)

	logLevel = viper.GetString("log_level")
	logFile = viper.GetString("log_file")
	logMaxSize = viper.GetInt("log_max_size")
	logMaxBackups = viper.GetInt("log_max_backups")
	logMaxAge = viper.GetInt("log_max_age")

	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().Msg("Crowdsec API key is not set")
	}
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().Msg("Crowdsec URL is not set")
	}

	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	mikrotikHost = viper.GetString("mikrotik_host")

	username = viper.GetString("mikrotik_user")
	if username == "" {
		log.Fatal().Msg("Mikrotik username is not set")
	}

	password = viper.GetString("mikrotik_pass")
	if password == "" {
		log.Fatal().Msg("Mikrotik password is not set")
	}

	useTLS = viper.GetBool("mikrotik_tls")
	useIPV6 = viper.GetBool("mikrotik_ipv6")

	all := viper.AllSettings()
	delete(all, "mikrotik_pass")
	delete(all, "crowdsec_bouncer_api_key")

	log.Printf("Using config: %+v", all)
}
