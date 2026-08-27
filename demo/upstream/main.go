// Mock destination for the xlate demo.
//
// It stands in for the two "other side" systems: a payment provider and a
// freight carrier. It answers in each side's own vocabulary so the return
// leg has something real to reverse-map.
//
// Its own module so it never becomes a dependency of the gateway.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9090", "listen address")
	quiet := flag.Bool("quiet", false, "do not log received bodies")
	flag.Parse()

	reply := func(name string, body map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if !*quiet {
				log.Printf("%s <- %s", name, b)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		}
	}

	// Side B vocabularies: what each destination speaks natively.
	http.HandleFunc("/v2/payments", reply("PSP  ", map[string]any{
		"payment_proof": "P-10041", "cust_id": "C-7781",
		"value": 2499, "ccy": "USD", "created_epoch": 1709283600,
		"status": "settled",
	}))
	http.HandleFunc("/shipments", reply("FRGHT", map[string]any{
		"shipment_id": "S-42", "destination_zip": "10001",
		"dispatched_on": 1709283600000, "carrier": "Freightline",
	}))
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	log.Printf("mock destination listening on %s", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
