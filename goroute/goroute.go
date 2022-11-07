package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Result struct {
	IP            string
	HOP           int
	TimeElapsedMS float64
}

func createICMPPacket(id int, seq int) []byte {
	// Create a new ICMP message
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: id, Seq: seq,
			Data: []byte("GO-ROUTE"),
		},
	}
	// Marshal the message
	b, err := m.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func waitResponses(c *icmp.PacketConn, timeout time.Duration,
	startTime float64, targetHost string, maxTTL int, id int, wg *sync.WaitGroup) {

	// create a new Timer
	timer := time.NewTimer(timeout)

	// create a channel to receive the results
	results := make(map[int]Result, 0)

	// reply buffer
	reply := make([]byte, 1500)

	go func() {
		for {
			// Read the response
			n, peer, err := c.ReadFrom(reply)
			if err != nil {
				break
			}

			// Parse the response
			rm, err := icmp.ParseMessage(1, reply[:n])
			if err != nil {
				log.Println("failed to parse ICMPv4 message: ", err)
				break
			}

			// check type of ICMP message
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				t, ok := rm.Body.(*icmp.Echo)
				if !ok {
					log.Println("not an echo reply")
					break
				}

				// we skip if the response does not
				// come from the target host
				if peer.String() != targetHost {
					continue
				}

				// store results in a map keyed by the sequence number
				r := Result{
					IP:            peer.String(),
					HOP:           t.Seq,
					TimeElapsedMS: float64(time.Now().UnixNano()/1000000) - startTime,
				}

				// store the result
				results[t.Seq] = r

				// if we've received an echo reply from targetHost
				// we can signal we are done
				// done <- struct{}{}
				// return
			case ipv4.ICMPTypeTimeExceeded:
				// cast to icmp.TimeExceeded
				t, ok := rm.Body.(*icmp.TimeExceeded)
				if !ok {
					log.Println("failed to cast to icmp.TimeExceeded")
					break
				}

				// icmp.TimeExceeded contains the original packet
				// so we grab IPv4 header and ICMP header
				ipHdr, err := icmp.ParseIPv4Header(t.Data)
				if err != nil {
					log.Println("failed to parse IPv4 header", err)
					break
				}

				// grab the ICMP header
				if icmpMsg, err := icmp.ParseMessage(1, t.Data[ipHdr.Len:]); err == nil {
					if msg, ok := icmpMsg.Body.(*icmp.Echo); ok && msg.ID == id {
						r := Result{
							IP:            peer.String(),
							HOP:           msg.Seq,
							TimeElapsedMS: float64(time.Now().UnixNano()/1000000) - startTime,
						}
						results[msg.Seq] = r
					}
				} else {
					log.Println("failed to parse inner ICMPv4 message", err)
				}
			default:
				log.Printf("Unexpected response %+v: %s", rm, peer.String())
			}
		}
	}()

	// wait for the timer to expire
	<-timer.C

	// print the results
	for i := 1; i <= maxTTL; i++ {
		if r, ok := results[i]; ok {
			fmt.Printf("%d\t%s\t%.2f ms\n", r.HOP, r.IP, r.TimeElapsedMS)
			if r.IP == targetHost {
				break
			}
		} else {
			fmt.Printf("%d\t*\n", i)
		}
	}

	wg.Done()
}

var (
	host    = flag.String("host", "", "host to traceroute")
	maxHops = flag.Int("max-hops", 30, "max hops")
	timeout = flag.Duration("timeout", 2*time.Second, "timeout")
	probes  = flag.Int("probes", 3, "number of probes per hop")
)

func main() {
	flag.Parse()

	// check host is not empty
	if *host == "" {
		flag.Usage()
		os.Exit(1)
	}

	// start listening for ICMP messages
	c, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	id := os.Getpid() & 0xffff

	remoteHost, err := net.ResolveIPAddr("ip4", *host)
	if err != nil {
		log.Fatal(err)
	}

	// create a wait group to wait for all the goroutines to finish
	wg := &sync.WaitGroup{}

	// output message
	fmt.Printf("traceroute to %s (%s), %d hops max, timeout %s, start time %s\n",
		*host, remoteHost.String(), *maxHops, *timeout, time.Now().Format(time.RFC3339))

	// start time in milliseconds
	startTime := float64(time.Now().UnixNano()) / 1000000

	wg.Add(1)
	go waitResponses(c, *timeout,
		startTime, remoteHost.IP.String(), *maxHops, id, wg)

	for ttl := 1; ttl <= *maxHops; ttl++ {
		// Set the TTL
		if err := c.IPv4PacketConn().SetTTL(ttl); err != nil {
			log.Println("failed to set TTL: ", err)
			continue
		}

		// send N probes for each message
		for i := 0; i < *probes; i++ {

			// Create an ICMP packet
			b := createICMPPacket(id, ttl)

			// Send the packet
			if _, err := c.WriteTo(b, remoteHost); err != nil {
				log.Println("failed to write packet: ", err)
			}
		}
	}

	wg.Wait()
}
