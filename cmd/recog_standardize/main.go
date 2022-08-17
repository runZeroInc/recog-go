package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/runZeroInc/recog-go"
)

type set map[string]struct{}

var stdIdentifiers = map[string]set{
	"device":          nil,
	"fields":          nil,
	"hw_family":       nil,
	"hw_product":      nil,
	"os_architecture": nil,
	"os_family":       nil,
	"os_product":      nil,
	"service_family":  nil,
	"service_product": nil,
	"vendor":          nil,
}

var curIdentifiers = map[string]set{
	"device":          make(set),
	"fields":          make(set),
	"hw_family":       make(set),
	"hw_product":      make(set),
	"os_architecture": make(set),
	"os_family":       make(set),
	"os_product":      make(set),
	"service_family":  make(set),
	"service_product": make(set),
	"vendor":          make(set),
}

func (s *set) add(key string) {
	(*s)[key] = struct{}{}
}

func (s set) keys() []string {
	var keys []string
	for key := range s {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var (
	foundNew     bool
	foundRemoved bool

	asyncErr  = atomic.Value{}
	recogHome = os.Getenv("RECOG_HOME")

	write = flag.Bool("w", false, "Write newly discovered identifiers to the identifiers reference files")
	zero  = flag.Bool("z", false, "Whether to exit with a zero exit code on success")
)

func main() {
	log.SetFlags(0)
	if recogHome == "" {
		recogHome = "./recog"
	}

	flag.Usage = defaultUsage()
	flag.Parse()
	if flag.NArg() == 0 {
		invalidUsage()
	}

	for identifier := range stdIdentifiers {
		current, err := loadIdentifiers(identifier)
		if err != nil {
			log.Fatalln(err)
		}
		stdIdentifiers[identifier] = current
	}

	wg := sync.WaitGroup{}
	pwg := sync.WaitGroup{}
	errCh := waitForErrs()
	msgCh := waitForMsgs()
	paramCh := waitForParams(&pwg)

	for _, arg := range flag.Args() {
		files, err := filepath.Glob(arg)
		if err != nil {
			log.Fatalf("failed to expand file paths: %s", err)
		} else if len(files) == 0 {
			invalidUsage()
		}

		for _, file := range files {
			go extractParams(file, &wg, errCh, paramCh)
			wg.Add(1)
		}
	}

	wg.Wait()
	close(paramCh)
	pwg.Wait()

	if err := asyncErr.Load(); err != nil {
		log.Fatalln(err)
	}

	for identifier := range stdIdentifiers {
		go handleChanges(curIdentifiers[identifier], stdIdentifiers[identifier], strings.ToUpper(identifier), identifier, &wg, errCh, msgCh)
		wg.Add(1)
	}

	wg.Wait()
	close(errCh)
	close(msgCh)

	exitCode := 0
	if !*zero && (foundNew || foundRemoved) {
		exitCode = 1
	}
	os.Exit(exitCode)
}

func defaultUsage() func() {
	return func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage %s [options] XML_FINGERPRINT_FILE1 ...\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Verifies that each fingerprint asserts known identifiers.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Known identifiers are stored in reference files in the path: \n")
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\n", filepath.Join(recogHome, "identifiers"))
		fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
		flag.PrintDefaults()
	}
}

func invalidUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Missing XML fingerprint files\n")
	flag.Usage()
	os.Exit(1)
}

func extractParams(file string, wg *sync.WaitGroup, errCh chan error, paramCh chan *recog.FingerprintParam) {
	defer wg.Done()

	f, err := os.Open(file)
	if err != nil {
		errCh <- err
		return
	}

	defer f.Close()

	var elem string
	decoder := xml.NewDecoder(f)
	for {
		t, _ := decoder.Token()
		if t == nil {
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			elem = se.Name.Local
			if elem == "param" {
				var param recog.FingerprintParam
				decoder.DecodeElement(&param, &se)
				paramCh <- &param
			}
		}
	}
}

func waitForErrs() chan error {
	errCh := make(chan error, 1)
	go func() {
		for err := range errCh {
			asyncErr.CompareAndSwap(nil, err)
			log.Printf("error: %s", err)
		}
	}()
	return errCh
}

func waitForMsgs() chan string {
	msgCh := make(chan string, 1)
	go func() {
		for msg := range msgCh {
			log.Println(msg)
		}
	}()
	return msgCh
}

func waitForParams(wg *sync.WaitGroup) chan *recog.FingerprintParam {
	paramCh := make(chan *recog.FingerprintParam, 1_000)
	wg.Add(1)
	go func() {
		for param := range paramCh {
			addToSet(curIdentifiers["fields"], param.Name)
			if param.Position != "0" || strings.TrimSpace(param.Value) == "" || strings.Contains(param.Value, "{") {
				continue
			}
			switch param.Name {
			case "os.vendor", "service.vendor", "service.component.vendor", "hw.vendor":
				addToSet(curIdentifiers["vendor"], param.Value)
			case "os.device", "service.device", "hw.device":
				addToSet(curIdentifiers["device"], param.Value)
			case "os.arch":
				addToSet(curIdentifiers["os_architecture"], param.Value)
			case "os.product":
				addToSet(curIdentifiers["os_product"], param.Value)
			case "os.family":
				addToSet(curIdentifiers["os_family"], param.Value)
			case "hw.product":
				addToSet(curIdentifiers["hw_product"], param.Value)
			case "hw.family":
				addToSet(curIdentifiers["hw_family"], param.Value)
			case "service.product", "service.component.product":
				addToSet(curIdentifiers["service_product"], param.Value)
			case "service.family":
				addToSet(curIdentifiers["service_family"], param.Value)
			}
		}
		wg.Done()
	}()
	return paramCh
}

func addToSet(s set, value string) {
	s.add(value)
}

func loadIdentifiers(identifier string) (set, error) {
	data, err := os.ReadFile(filepath.Join(recogHome, "identifiers", fmt.Sprintf("%s.txt", identifier)))
	if err != nil {
		return nil, fmt.Errorf("failed to load %q identifiers: %s; is $RECOG_HOME configured", identifier, err)
	}

	identifiers := make(set)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		identifiers.add(scanner.Text())
	}

	return identifiers, nil
}

func writeIdentifiers(identifier string, keys []string) error {
	path := filepath.Join(recogHome, "identifiers", fmt.Sprintf("%s.txt", identifier))
	keys = append(keys, "") // append a newline to the end of the file
	data := strings.Join(keys, "\n")
	return os.WriteFile(path, []byte(data), 0o644)
}

func handleChanges(current set, original set, msg string, identifier string, wg *sync.WaitGroup, errCh chan error, msgCh chan string) {
	defer wg.Done()

	changes := false
	for _, key := range original.keys() {
		if _, ok := current[key]; ok {
			continue
		}

		msgCh <- fmt.Sprintf("%s REMOVED VALUE: %s", msg, key)
		foundRemoved = true
		changes = true
	}

	for _, key := range current.keys() {
		if _, ok := original[key]; ok {
			continue
		}

		msgCh <- fmt.Sprintf("%s NEW VALUE: %s", msg, key)
		foundNew = true
		changes = true
	}

	if *write && changes {
		if err := writeIdentifiers(identifier, current.keys()); err != nil {
			errCh <- err
		}
	}
}
