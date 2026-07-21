package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog/log"

	"github.com/go-routeros/routeros/v3"
)

const updateDurationTolerance = 1 * time.Minute

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(mikrotikHost, username, password, nil)
	}
	return routeros.Dial(mikrotikHost, username, password)
}

func (mal *mikrotikAddrList) initMikrotik() {
	log.Info().Msg("connecting to mikrotik")

	c, err := dial()
	if err != nil {
		log.Fatal().Err(err).Str("host", mikrotikHost).Str("username", username).Bool("useTLS", useTLS).Msg("connection failed")
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
		initCmd := fmt.Sprintf("/%s/firewall/address-list/print ?list=%s =.proplist=.id,address,timeout", proto, mikrotikList)
		r, err := c.RunArgs(strings.Split(initCmd, " "))
		if err != nil {
			log.Fatal().Str("protocol", proto).Str("list", mikrotikList).Err(err).Msg("address-list print failed")
		}
		log.Info().Str("protocol", proto).Str("list", mikrotikList).Msgf("fill %d entry in internal addrList", len(r.Re))
		for _, v := range r.Re {
			mal.cache[v.Map["address"]] = mikrotikAddrListData{v.Map[".id"], v.Map["timeout"]}
		}
	}
}

func (mal *mikrotikAddrList) add(decision *models.Decision) {
	log.Debug().
		Str("origin", *decision.Origin).
		Str("value", *decision.Value).
		Str("scenario", *decision.Scenario).
		Str("duration", *decision.Duration).
		Str("scope", *decision.Scope).
		Msg("new decision")

	var proto string
	if strings.Contains(*decision.Value, ":") {
		if !useIPV6 {
			log.Debug().Str("address", *decision.Value).Msg("ignore adding address. IPv6 disabled")
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

	if data, ok := mal.cache[address]; ok {
		//update
		mtDuration, err := time.ParseDuration(data.Duration)
		if err != nil {
			log.Fatal().Err(err).Str("address", address).Msg("time parse error(data.Duration)")
		}
		csDuration, err := time.ParseDuration(*decision.Duration)
		if err != nil {
			log.Fatal().Err(err).Str("address", address).Msg("time parse error(decision.Duration)")
		}
		diff := (mtDuration - csDuration).Abs()

		if diff < updateDurationTolerance {
			log.Debug().Str("protocol", proto).Str("address", address).
				Str("duration_mt", data.Duration).Str("duration_local", *decision.Duration).
				Msg("skipped. same duration")
			return
		}

		updateCmd := fmt.Sprintf("/%s/firewall/address-list/set =numbers=%s =comment=%s =timeout=%s", proto, data.ID, comment, *decision.Duration)
		_, err = mal.c.RunArgs(strings.Split(updateCmd, " "))
		if err != nil {
			log.Error().Str("protocol", proto).Str("address", address).Str("id", data.ID).Err(err).Msg("address-list update cmd failed")
		} else {
			log.Info().Str("protocol", proto).Str("address", address).Str("id", data.ID).Msg("updated in mikrotik")
		}

	} else {
		// add

		addCmd := fmt.Sprintf("/%s/firewall/address-list/add =list=%s =address=%s =comment=%s =timeout=%s", proto, mikrotikList, address, comment, *decision.Duration)

		r, err := mal.c.RunArgs(strings.Split(addCmd, " "))
		if err != nil {
			log.Error().Err(err).Str("protocol", proto).Str("address", address).Msg("address-list add cmd failed")
		} else {
			mal.cache[address] = mikrotikAddrListData{r.Done.List[0].Value, *decision.Duration} //msz
			log.Info().Str("protocol", proto).Str("address", address).Msg("blocked in mikrotik")
		}
	}
}

func (mal *mikrotikAddrList) remove(decision *models.Decision) {
	log.Debug().
		Str("origin", *decision.Origin).
		Str("value", *decision.Value).
		Str("scenario", *decision.Scenario).
		Str("duration", *decision.Duration).
		Str("scope", *decision.Scope).
		Msg("removed decision")

	var proto string
	if strings.Contains(*decision.Value, ":") {
		log.Debug().Str("address", *decision.Value).Msg("ignore adding address. IPv6 disabled")
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

	if data, ok := mal.cache[address]; ok {
		delCmd := fmt.Sprintf("/%s/firewall/address-list/remove =numbers=%s", proto, data.ID)
		_, err := mal.c.RunArgs(strings.Split(delCmd, " "))
		if err != nil {
			log.Error().Err(err).Str("protocol", proto).Str("address", address).Str("id", data.ID).Msg("address-list remove cmd failed")
		} else {
			log.Info().Str("protocol", proto).Str("address", address).Str("id", data.ID).Msg("removed from mikrotik")
		}

		delete(mal.cache, address)
	} else {
		log.Warn().Str("protocol", proto).Str("address", address).Msg("not found in local cache. remove failed")
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
