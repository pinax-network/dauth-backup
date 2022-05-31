package authenticator

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
	"strings"
)

type IpAllowList struct {
	ipNets map[*net.IPNet]int
	ips    map[string]int
}

type IpLimitCategory struct {
	Rate int      `yaml:"rate"`
	Ips  []string `yaml:"ips"`
}

func NewIpAllowList() *IpAllowList {

	limits := &IpAllowList{}
	limits.ipNets = make(map[*net.IPNet]int)
	limits.ips = make(map[string]int)

	return limits
}

func NewIpAllowListFromFile(path string) (*IpAllowList, error) {

	limits := NewIpAllowList()

	b, err := ioutil.ReadFile(path)
	limitsFile := make(map[string]IpLimitCategory)

	if err != nil {
		return nil, fmt.Errorf("failed to open limits file: %w", err)
	}

	err = yaml.Unmarshal(b, limitsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	for _, cat := range limitsFile {
		for _, ipString := range cat.Ips {
			if strings.Contains(ipString, "/") {
				_, ipNet, err := net.ParseCIDR(ipString)

				if err != nil {
					return nil, fmt.Errorf("failed to parse cidr: %w", err)
				}
				limits.ipNets[ipNet] = cat.Rate
			} else {
				ip := net.ParseIP(ipString)

				if ip == nil {
					return nil, fmt.Errorf("failed to parse ip: %w", err)
				}
				limits.ips[ip.String()] = cat.Rate
			}
		}
	}

	return limits, nil
}

func (w *IpAllowList) GetRate(ipString string) (int, error) {

	ip := net.ParseIP(ipString)

	if ip == nil {
		return 0, fmt.Errorf("failed to parse ip: %s", ipString)
	}

	if _, ok := w.ips[ip.String()]; ok {
		return w.ips[ip.String()], nil
	}

	for k, v := range w.ipNets {
		if k.Contains(ip) {
			return v, nil
		}
	}

	return 0, fmt.Errorf("ip not whitelisted: %s", ipString)
}
