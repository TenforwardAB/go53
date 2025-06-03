package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	host   = "127.0.0.1"
	port   = "53"
	name   = "www.go53.test"
	qtype  = "A"
	runs   = 1000
	worker = 10 // parallel queries (can be 1 for serial)
)

func main() {
	var (
		times []time.Duration
		mu    sync.Mutex
		wg    sync.WaitGroup
	)

	start := time.Now()
	taskCh := make(chan struct{}, runs)
	for i := 0; i < runs; i++ {
		taskCh <- struct{}{}
	}
	close(taskCh)

	wg.Add(worker)
	for w := 0; w < worker; w++ {
		go func() {
			defer wg.Done()
			for range taskCh {
				t1 := time.Now()
				cmd := exec.Command("dig",
					fmt.Sprintf("@%s", host),
					"-p", port,
					name, qtype, "+timeout=1", "+tries=1", "+noquestion", "+stats", "+nocmd")
				out, err := cmd.CombinedOutput()
				elapsed := time.Since(t1)
				if err != nil {
					fmt.Printf("ERROR: %s\n", err)
					continue
				}
				if !strings.Contains(string(out), "NOERROR") && !strings.Contains(string(out), "status:") {
					fmt.Printf("Bad response: %s\n", string(out))
					continue
				}
				mu.Lock()
				times = append(times, elapsed)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	total := time.Since(start)

	if len(times) == 0 {
		fmt.Println("No successful responses.")
		return
	}

	var min, max, sum time.Duration
	min, max = times[0], times[0]
	for _, t := range times {
		sum += t
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
	}

	fmt.Printf("\nDNS benchmark for %d queries (%d parallel)\n", runs, worker)
	fmt.Printf("Avg:  %.2f ms\n", float64(sum.Microseconds())/1000/float64(len(times)))
	fmt.Printf("Min:  %.2f ms\n", float64(min.Microseconds())/1000)
	fmt.Printf("Max:  %.2f ms\n", float64(max.Microseconds())/1000)
	fmt.Printf("QPS:  %.1f\n", float64(len(times))/total.Seconds())
}
