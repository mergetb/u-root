// Copyright 2017 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// dhclient sets up DHCP.
//
// Synopsis:
//     dhclient [OPTIONS...]
//
// Options:
//     -timeout:  lease timeout in seconds
//     -renewals: number of DHCP renewals before exiting
//     -verbose:  verbose output
package main

import (
	"context"
	"flag"
	"log"
	"regexp"
	"time"

	"github.com/mergetb/u-root/pkg/dhclient"
	"github.com/vishvananda/netlink"
)

var (
	ifName  = "^e.*"
	timeout = flag.Int("timeout", 1, "Lease timeout in seconds")
	retry   = flag.Int("retry", 20, "Max number of attempts for DHCP clients to send requests. -1 means infinity")
	verbose = flag.Bool("v", true, "Verbose output")
	ipv4    = flag.Bool("ipv4", true, "use IPV4")
	ipv6    = flag.Bool("ipv6", false, "use IPV6")
)

func main() {
	flag.Parse()
	if len(flag.Args()) > 1 {
		log.Fatalf("only one re")
	}

	if len(flag.Args()) > 0 {
		ifName = flag.Args()[0]
	}

	ifRE := regexp.MustCompilePOSIX(ifName)

	ifnames, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Can't get list of link names: %v", err)
	}

	var filteredIfs []netlink.Link
	for _, iface := range ifnames {
		if ifRE.MatchString(iface.Attrs().Name) {
			filteredIfs = append(filteredIfs, iface)
		}
	}

	if len(filteredIfs) == 0 {
		log.Fatalf("No interfaces match %s", ifName)
	}

	configureAll(filteredIfs)
}

func configureAll(ifs []netlink.Link) {
	packetTimeout := time.Duration(*timeout) * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), packetTimeout*time.Duration(1<<uint(*retry)))
	defer cancel()

	c := dhclient.Config{
		Timeout: packetTimeout,
		Retries: *retry,
	}
	if *verbose {
		c.LogLevel = dhclient.LogSummary
	}
	r := dhclient.SendRequests(ctx, ifs, *ipv4, *ipv6, c)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Done with dhclient: %v", ctx.Err())
			return

		case result, ok := <-r:
			if !ok {
				log.Printf("Configured all interfaces.")
				return
			}
			if result.Err != nil {
				log.Printf("Could not configure %s: %v", result.Interface.Attrs().Name, result.Err)
			} else if err := result.Lease.Configure(); err != nil {
				log.Printf("Could not configure %s: %v", result.Interface.Attrs().Name, err)
			} else {
				log.Printf("Configured %s with %s", result.Interface.Attrs().Name, result.Lease)
			}
		}
	}
}
