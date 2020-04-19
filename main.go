package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Client represents the clients found
type Client struct {
	MAC          string    `json:"mac"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Power        int       `json:"power"`
	Packets      int       `json:"packets"`
	BSSID        string    `json:"bssid"`
	Probes       string    `json:"probes"`
	Organization string    `json:"organization"`
}

var dir *string // directory where the public directory is in
var port *int
var csvFile *string
var clientsFound []Client

func init() {

	d, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	dir = flag.String("dir", d, "directory where the public directory is in")
	port = flag.Int("p", 12121, "the port where the server starts")
	csvFile = flag.String("f", "dump-01.csv", "airodump-ng csv file to parse")
	flag.Parse()
}

func main() {
	go getData()
	serve()
}

func getData() {
	for {
		clientsFound = parseCsv(*csvFile)
		time.Sleep(10 * time.Second)
	}
}

func serve() {
	mux := http.NewServeMux()
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir(*dir+"/public"))))
	mux.HandleFunc("/", index)
	mux.HandleFunc("/clients", clients)
	server := &http.Server{
		Addr:    "0.0.0.0:" + strconv.Itoa(*port),
		Handler: mux,
	}
	fmt.Println("Started netnet server at", server.Addr)
	go getData()
	server.ListenAndServe()
}

// index for web server
func index(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles(*dir + "/public/index.html")
	t.Execute(w, nil)
}

// index for web server
func clients(w http.ResponseWriter, r *http.Request) {
	str, err := json.MarshalIndent(clientsFound, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(str))
}

// https://en.wikipedia.org/wiki/MAC_address
// Addresses can either be universally administered addresses (UAA) or locally administered addresses (LAA).
// A universally administered address is uniquely assigned to a device by its manufacturer.
// The first three octets (in transmission order) identify the organization that issued the identifier and
// are known as the organizationally unique identifier (OUI).
// Universally administered and locally administered addresses are distinguished by setting the
// second-least-significant bit of the first octet of the address. This bit is also referred to as the U/L bit,
// short for Universal/Local, which identifies how the address is administered. If the bit is 0, the address
// is universally administered. If it is 1, the address is locally administered.

// Check if this is a locally administered MAC or not
func isLocalMAC(MAC string) bool {
	first, err := strconv.ParseInt(MAC[:2], 16, 32)
	if err != nil {
		log.Fatal(err)
	}
	if (first>>1)&1 == 1 {
		return true
	}
	return false
}

// parsing the csv dump from airodump-ng
func parseCsv(file string) (clients []Client) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	s := string(content)
	csvdata := strings.Split(s, "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs")

	// Parse the file
	r := csv.NewReader(strings.NewReader(csvdata[1]))
	// set to dynamic number of columns
	r.FieldsPerRecord = -1
	timeParseLayout := "2006-01-02 15:04:05"

	ouidb := parseOui()
	ciddb := parseCid()

	// ACCESS POINTS

	// TO-DO

	// CLIENTS

	// Iterate through the client records
	for {
		// Read each record from csv
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		firstSeen, err := time.Parse(timeParseLayout, strings.TrimSpace(record[1]))
		lastSeen, err := time.Parse(timeParseLayout, strings.TrimSpace(record[2]))
		if err != nil {
			fmt.Println("Cannot parse dates:", err)
		}
		power, err := strconv.Atoi(strings.TrimSpace(record[3]))
		packets, err := strconv.Atoi(strings.TrimSpace(record[4]))
		if err != nil {
			fmt.Println("Cannot parse values:", err)
		}

		c := Client{
			MAC:       strings.ReplaceAll(record[0], ":", "-"),
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
			Power:     power,
			Packets:   packets,
			BSSID:     record[5],
			Probes:    record[6],
		}
		if isLocalMAC(c.MAC) {
			cid := strings.TrimSpace(ciddb[c.MAC[:8]])
			if cid != "" {
				c.Organization = cid
			} else {
				c.Organization = "LOCAL"
			}

		} else {
			oui := strings.TrimSpace(ouidb[c.MAC[:8]])
			c.Organization = oui
		}

		clients = append(clients, c)
	}
	return
}

// Parsing the OUI from http://standards-oui.ieee.org/oui.txt
// OUI is organizational unique identifier https://en.wikipedia.org/wiki/Organizationally_unique_identifier
func parseOui() (oui map[string]string) {
	file, err := os.Open("oui.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	oui = make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(hex)") {
			str := strings.Split(line, "   (hex)		")
			oui[str[0]] = str[1]
		}
	}
	return
}

// Parsing the CID from http://standards-oui.ieee.org/cid/cid.txt
// CID is company ID https://standards.ieee.org/products-services/regauth/cid/index.html
func parseCid() (cid map[string]string) {
	file, err := os.Open("cid.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	cid = make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(hex)") {
			str := strings.Split(line, "                      (hex)                         ")
			cid[str[0]] = str[1]
		}
	}
	return
}
