package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog/log"

	"github.com/go-routeros/routeros/v3"
)

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(mikrotikHost, username, password, nil)
	}
	return routeros.Dial(mikrotikHost, username, password)
}

func (mal *mikrotikAddrList) initMikrotik() {
	log.Info().Msg("Connecting to mikrotik")

	c, err := dial()
	if err != nil {
		log.Fatal().Err(err).Str("host", mikrotikHost).Str("username", username).Bool("useTLS", useTLS).Msg("Connection failed")
	}

	if async {
		c.Async()
	}

	mal.c = c

	mal.cache = make(map[string]mikrotikAddrListData)

	protos := []string{"ip"}

	if useIPV6 {
		protos = append(protos, "ipv6")
	}

	for _, proto := range protos {
		log.Info().Msgf("mikrotik %s list addr", proto)
		initCmd := fmt.Sprintf("/%s/firewall/address-list/print ?list=BAN =.proplist=.id,address,timeout", proto)
		r, err := c.RunArgs(strings.Split(initCmd, " "))
		if err != nil {
			log.Fatal().Err(err).Msg("address-list print failed")
		}
		log.Info().Msgf("fill %d entry in internal %s addrList", len(r.Re), proto)
		for _, v := range r.Re {
			mal.cache[v.Map["address"]] = mikrotikAddrListData{v.Map[".id"], v.Map["timeout"]}
		}
	}
}

func (mal *mikrotikAddrList) add(decision *models.Decision) {
	log.Debug().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	var proto string
	if strings.Contains(*decision.Value, ":") {
		if !useIPV6 {
			log.Debug().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
			return
		}
		proto = "ipv6"

	} else {
		proto = "ip"
	}

	var address string
	if *decision.Scope == "Ip" && proto == "ipv6" {
		address = fmt.Sprintf("%s/128", *decision.Value)
	} else {
		address = *decision.Value
	}

	comment := fmt.Sprintf("CS:%s:%s", *decision.Origin, *decision.Scenario)

	if data, ok :=  mal.cache[address]; ok {
		//update
		mtDuration, err := time.ParseDuration(data.Duration)
		if err != nil {
			log.Fatal().Err(err).Msgf("time parse error")
		}
		csDuration, err := time.ParseDuration(*decision.Duration)
		if err != nil {
			log.Fatal().Err(err).Msgf("time parse error")
		}
		diff := (mtDuration - csDuration).Abs()

		if diff < time.Minute * 5  {
			log.Debug().Msgf("%s skipped. same duration", address)
			return
		}

		log.Debug().Msgf("Verify address %s in mikrotik", address)
		checkCmd := fmt.Sprintf("/%s/firewall/address-list/print =.proplist=address,timeout ?list=BAN ?.id=%s", proto, data.ID)

		r, err := mal.c.RunArgs(strings.Split(checkCmd, " "))
		if err != nil {
			log.Fatal().Err(err).Msgf("%s address-list search cmd failed", proto)
		}

		if len(r.Re) == 1 && r.Re[0].Map["address"] == address {
			updateCmd := fmt.Sprintf("/%s/firewall/address-list/set =numbers=%s =comment=%s =timeout=%s", proto, data.ID, comment, *decision.Duration)
			_, err = mal.c.RunArgs(strings.Split(updateCmd, " "))
			if err != nil {
				log.Error().Err(err).Msgf("%s address-list update cmd failed", proto)
			}
			log.Info().Msgf("%s updated in mikrotik", address)
		} else {
			log.Fatal().Msgf("%s not updated mikrotik", address)
		}

	} else {
		// add

		addCmd := fmt.Sprintf("/%s/firewall/address-list/add =list=BAN =address=%s =comment=%s =timeout=%s", proto, address, comment, *decision.Duration)

		r, err := mal.c.RunArgs(strings.Split(addCmd, " "))
		if err != nil {
			log.Error().Err(err).Msgf("%s address-list add cmd failed", proto)
		} else {
			mal.cache[address] = mikrotikAddrListData{r.Done.List[0].Value, *decision.Duration} //msz
			log.Info().Msgf("%s blocked in mikrotik", address)
		}
	}
}

func (mal *mikrotikAddrList) remove(decision *models.Decision) {
	log.Debug().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	var proto string
	if strings.Contains(*decision.Value, ":") {
		log.Debug().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
		if !useIPV6 {
			return
		}
		proto = "ipv6"
	} else {
		proto = "ip"
	}

	var address string
	if *decision.Scope == "Ip" && proto == "ipv6" {
		address = fmt.Sprintf("%s/128", *decision.Value)
	} else {
		address = *decision.Value
	}

	if data, ok :=  mal.cache[address]; ok {
		log.Debug().Msgf("Verify address %s in mikrotik", address)
		checkCmd := fmt.Sprintf("/%s/firewall/address-list/print =.proplist=address ?list=BAN ?.id=%s", proto, data.ID)
		r, err := mal.c.RunArgs(strings.Split(checkCmd, " "))
		if err != nil {
			log.Fatal().Err(err).Msgf("%s address-list search cmd failed", proto)
		}

		if len(r.Re) == 1 && r.Re[0].Map["address"] == address {
			delCmd := fmt.Sprintf("/%s/firewall/address-list/remove =numbers=%s", proto, data.ID)
			_, err = mal.c.RunArgs(strings.Split(delCmd, " "))
			if err != nil {
				log.Error().Err(err).Msgf("%s address-list remove cmd failed", proto)
			}
			log.Info().Msgf("%s removed from mikrotik", address)
		} else {
			log.Debug().Msgf("%s already removed from mikrotik", address)
		}
		delete(mal.cache, address)

	} else {
		log.Debug().Msgf("%s not find in local cache", address)
	}
}

func (mal *mikrotikAddrList) decisionProcess(streamDecision *models.DecisionsStreamResponse) {

	for _, decision := range streamDecision.Deleted {
		mal.remove(decision)
	}
	for _, decision := range streamDecision.New {
		mal.add(decision)
	}
}
