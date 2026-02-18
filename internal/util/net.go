// Copyright (c) 2026 Abdurakhman Rakhmankulov
//
// Licensed under the MIT License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://opensource.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package util provides utility functions for network operations.
package util

import (
	"net"
	"strings"
)

const (
	maxIPExpansionLimit = 1000
	ipv6AddressLength   = 16
	ipRangePartsCount   = 2
)

// IsCIDR checks if a string is a valid CIDR notation
func IsCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsIP checks if a string is a valid IP address
func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ParseIPRange parses an IP range in format "IP-IP" or "IP/CIDR"
func ParseIPRange(rangeStr string) ([]string, error) {
	switch {
	case strings.Contains(rangeStr, "/"):
		// CIDR notation
		_, ipNet, err := net.ParseCIDR(rangeStr)
		if err != nil {
			return nil, err
		}
		return expandIPNet(ipNet), nil
	case strings.Contains(rangeStr, "-"):
		// IP range notation (e.g., "192.168.1.1-192.168.1.100")
		return parseIPRangeDash(rangeStr)
	default:
		// Single IP
		if net.ParseIP(rangeStr) == nil {
			return nil, &net.ParseError{Type: "IP address", Text: rangeStr}
		}
		return []string{rangeStr}, nil
	}
}

// expandIPNet expands a CIDR to individual IP addresses (for small ranges)
func expandIPNet(ipNet *net.IPNet) []string {
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
		// Limit expansion to prevent memory issues with large ranges
		if len(ips) > maxIPExpansionLimit {
			break
		}
	}
	return ips
}

// parseIPRangeDash parses IP range in "IP-IP" format
func parseIPRangeDash(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != ipRangePartsCount {
		return nil, &net.ParseError{Type: "IP range", Text: rangeStr}
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, &net.ParseError{Type: "IP address", Text: rangeStr}
	}

	// Ensure startIP <= endIP
	if ipToInt(startIP) > ipToInt(endIP) {
		startIP, endIP = endIP, startIP
	}

	var ips []string
	for ip := startIP; !ipGreaterThan(ip, endIP); incIP(ip) {
		ips = append(ips, ip.String())
		// Limit expansion to prevent memory issues
		if len(ips) > maxIPExpansionLimit {
			break
		}
	}

	return ips, nil
}

// incIP increments an IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ipGreaterThan checks if ip1 > ip2
func ipGreaterThan(ip1, ip2 net.IP) bool {
	int1 := ipToInt(ip1)
	int2 := ipToInt(ip2)
	return int1 > int2
}

// ipToInt converts an IP address to a 128-bit integer
func ipToInt(ip net.IP) int64 {
	if len(ip) == ipv6AddressLength {
		return int64(ip[0])<<56 | int64(ip[1])<<48 | int64(ip[2])<<40 |
			int64(ip[3])<<32 | int64(ip[4])<<24 | int64(ip[5])<<16 |
			int64(ip[6])<<8 | int64(ip[7])
	}
	return int64(ip[0])<<24 | int64(ip[1])<<16 | int64(ip[2])<<8 | int64(ip[3])
}

// IsPrivateIP checks if an IP address is private
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // localhost
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 localhost
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// NormalizeIP normalizes an IP address string
func NormalizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// GetIPVersion returns the IP version ("4" or "6")
func GetIPVersion(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "4"
	}
	return "6"
}
