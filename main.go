package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Event is an interesting event that occurred in MySQL logs
//   - When it happened
//   - Which node in the cluster
//   - User friendly message
//   - Raw log lines
type Event struct {
	Datetime time.Time
	Node     string
	Message  string
	Raw      string
}

// EventMatcher represents whats needed to find an event MySQL logs
//   - Description of event
//   - Function to match the event signature
//   - Function to convert the raw text to an event
type EventMatcher struct {
	Description string
	Match       func(string) bool
	Get         func(*bufio.Scanner) Event
}

func matchEventSignature(line string, signature string) bool {
	match, _ := regexp.MatchString(signature, line)
	return match
}

var (
	printYellow  = color.New(color.FgYellow).SprintFunc()
	printRed     = color.New(color.FgRed).SprintFunc()
	printBlue    = color.New(color.FgBlue).SprintFunc()
	printGreen   = color.New(color.FgGreen).SprintFunc()
	printMagenta = color.New(color.FgMagenta).SprintFunc()
	printCyan    = color.New(color.FgCyan).SprintFunc()

	nodeColors = make([]interface{}, 3, 3)

	timeFormatDefault  = "2006-01-02 15:04:05"
	timeFormatWsrepSst = "20060102 15:04:05"
	timeFormatMysqld   = "060102 15:04:05"

	// Give each state a numeric value so shifts
	// to a lower state can be flagged
	shiftState = map[string]int{
		"ERROR":          10,
		"DESTROYED":      20,
		"CLOSED":         30,
		"OPEN":           40,
		"PRIMARY":        50,
		"JOINER":         60,
		"DONOR/DESYNCED": 70,
		"DONOR":          75,
		"JOINED":         80,
		"SYNCED":         90,
	}

	// Event matchers for all know events
	eventMatchers = []EventMatcher{
		EventMatcher{
			"Node is changing state",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: Shifting`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2015-10-28 16:36:52 10144 [Note] WSREP: Shifting PRIMARY -> JOINER (TO: 31389)
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				matcher := regexp.MustCompile(` Shifting (.*) -> (.*) \(TO: ([0-9]*\))`)
				matches := matcher.FindStringSubmatch(lines[0])

				message := fmt.Sprintf("  %s => ", matches[1])

				if shiftState[matches[1]] > shiftState[matches[2]] {
					message = message + printRed(matches[2])
				} else {
					message = message + printGreen(matches[2])
				}

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"Quorum results",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: Quorum results:`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2015-10-28 14:28:50 553 [Note] WSREP: Quorum results:
				//     version    = 3,
				//     component  = PRIMARY,
				//     conf_id    = 4,
				//     members    = 3/3 (joined/total),
				//     act_id     = 11152,
				//     last_appl. = -1,
				//     protocols  = 0/7/3 (gcs/repl/appl),
				//     group UUID = 98ed75de-7c05-11e5-9743-de4abc22bd11
				lines := scanLines(scanner, 9)

				eventTime := getTimeDefault(lines[0])
				matcher := regexp.MustCompile(`component  = (.*),`)
				matches := matcher.FindStringSubmatch(lines[2])
				component := matches[1]
				matcher = regexp.MustCompile(`members    = ([0-9]*)/([0-9]*) \(joined/total\),`)
				matches = matcher.FindStringSubmatch(lines[4])
				membersJoined := matches[1]
				membersTotal := matches[2]

				message := ""

				componentString := component
				if component == "PRIMARY" {
					componentString = printGreen(componentString)
				} else {
					componentString = printRed(componentString)
				}
				message += fmt.Sprintf("Component: %s, ", componentString)

				membersString := fmt.Sprintf("%s/%s", membersJoined, membersTotal)
				if membersJoined == membersTotal {
					membersString = printGreen(membersString)
				} else {
					membersString = printRed(membersString)
				}
				message += fmt.Sprintf("Members: %s", membersString)

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"State Transfer Required",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: State transfer required:`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2015-10-28 16:36:51 10144 [Note] WSREP: State transfer required:
				//     Group state: 98ed75de-7c05-11e5-9743-de4abc22bd11:31382
				//     Local state: 98ed75de-7c05-11e5-9743-de4abc22bd11:11152
				lines := scanLines(scanner, 3)
				eventTime := getTimeDefault(lines[0])

				groupState := strings.SplitN(lines[1], ":", 3)
				localState := strings.SplitN(lines[2], ":", 3)

				groupStateString := fmt.Sprintf("%s:%s", strings.Trim(groupState[1], " "), strings.Trim(groupState[2], " "))
				localStateString := fmt.Sprintf("%s:%s", strings.Trim(localState[1], " "), strings.Trim(localState[2], " "))
				if localState[2] == "-1" {
					localStateString = printRed(localStateString)
				} else {
					localStateString = printGreen(localStateString)
				}

				message := fmt.Sprintf("Group: %s, Local: %s", groupStateString, localStateString)

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"WSREP recovered position",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: Recovered position `)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-06-14 14:02:28 139993574066048 [Note] WSREP: Recovered position f3d1aa70-31a3-11e7-908c-f7a5ad9e63b1:40847697
				lines := scanLines(scanner, 1)
				eventTime := getTimeMysqld(lines[0])

				matcher := regexp.MustCompile(`Recovered position (.*):(.*)`)
				matches := matcher.FindStringSubmatch(lines[0])
				uuid := matches[1]
				seqno := matches[2]

				recoveredString := fmt.Sprintf("%s:%s", uuid, seqno)
				if seqno == "-1" {
					recoveredString = printRed(recoveredString)
				} else {
					recoveredString = printGreen(recoveredString)
				}

				message := fmt.Sprintf("Recovered position: %s", recoveredString)

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"Interruptor",
			func(line string) bool {
				return matchEventSignature(line, `SST disabled due to danger of data loss`)
			},
			func(scanner *bufio.Scanner) Event {
				// WSREP_SST: [ERROR] ############################################################################## (20170506 15:14:06.901)
				// WSREP_SST: [ERROR] SST disabled due to danger of data loss. Verify data and bootstrap the cluster (20170506 15:14:06.902)
				// WSREP_SST: [ERROR] ############################################################################## (20170506 15:14:06.904)
				lines := scanLines(scanner, 1)
				eventTime := getTimeWsrepSst(lines[0])

				message := printRed(`++++++++++ Interruptor ++++++++++`)

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"MySQL ended",
			func(line string) bool {
				return matchEventSignature(line, ` from pid file `)
			},
			func(scanner *bufio.Scanner) Event {
				// 170505 14:35:47 mysqld_safe mysqld from pid file /tmp/tmp-mysql.pid ended
				lines := scanLines(scanner, 1)

				eventTime := getTimeMysqld(lines[0])
				message := "PID ended"

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"MySQL normal shutdown",
			func(line string) bool {
				return matchEventSignature(line, `mysqld: Normal shutdown`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-05-05 14:35:45 139716968405760 [Note] /var/vcap/packages/mariadb/bin/mysqld: Normal shutdown
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])
				message := "Normal Shutdown"

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"MySQL startup",
			func(line string) bool {
				return matchEventSignature(line, `starting as process`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-05-06 16:53:13 140445682804608 [Note] /var/vcap/packages/mariadb/bin/mysqld (mysqld 10.1.18-MariaDB) starting as process 24588 ...
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])
				message := "MySQL startup"

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"InnoDB shutdown",
			func(line string) bool {
				return matchEventSignature(line, `InnoDB: Starting shutdown...`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-05-06 16:53:08 140348661906176 [Note] InnoDB: Starting shutdown...
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])
				message := "InnoDB shutdown"

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"InnoDB shutdown complete",
			func(line string) bool {
				return matchEventSignature(line, `mysqld: Shutdown complete`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-05-05 14:35:47 139716968405760 [Note] /var/vcap/packages/mariadb/bin/mysqld: Shutdown complete
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])
				message := "MySQL shutdown complete"

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"Primary not possible",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: no nodes coming from prim view`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-05-05  6:50:37 140137601001344 [Warning] WSREP: no nodes coming from prim view, prim not possible
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])
				message := "Primary not possible"

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"Cluster View",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: view\(`)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-06-14 10:11:35 139887269365504 [Note] WSREP: view(view_id(NON_PRIM,55433460,408) memb {
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])

				view := ""
				if strings.Contains(lines[0], "empty") {
					view = "empty"
				} else if strings.Contains(lines[0], "view_id") {
					matcher := regexp.MustCompile(`view\(view_id\(([A-Z_]*),`)
					matches := matcher.FindStringSubmatch(lines[0])
					view = matches[1]
				}

				message := fmt.Sprintf("WSREP view => %s", view)

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
		EventMatcher{
			"xtrabackup",
			func(line string) bool {
				return matchEventSignature(line, `WSREP: Running: `)
			},
			func(scanner *bufio.Scanner) Event {
				// 2017-06-14 19:10:58 140682204215040 [Note] WSREP: Running: 'wsrep_sst_xtrabackup-v2 --role 'joiner' --address '10.19.148.90' --datadir '/var/vcap/store/mysql/'   --parent '32691' --binlog 'mysql-bin' '
				lines := scanLines(scanner, 1)

				eventTime := getTimeDefault(lines[0])

				matcher := regexp.MustCompile(`--role '(.*)' --address '(.*?)' --`)
				matches := matcher.FindStringSubmatch(lines[0])
				role := matches[1]
				address := matches[2]

				message := ""
				if role == "joiner" {
					message = fmt.Sprintf("Joining from %s", address)
				} else if role == "donor" {
					message = fmt.Sprintf("Donating to %s", address)
				} else {
					message = "Oops :-o"
				}

				return Event{
					eventTime,
					"nodename",
					message,
					strings.Join(lines[:], "\n"),
				}
			},
		},
	}
)

func getTimeDefault(line string) time.Time {
	// "2006-01-02 15:04:05"
	t, err := time.Parse(timeFormatDefault, line[:19])

	if err != nil {
		fmt.Println("Oops")
	}

	return t
}

func getTimeWsrepSst(line string) time.Time {
	// "20060102 15:04:05"
	matcher := regexp.MustCompile(`([0-9]{8} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	matches := matcher.FindStringSubmatch(line)
	t, err := time.Parse(timeFormatWsrepSst, matches[1])

	if err != nil {
		fmt.Println("Oops")
	}

	return t
}

func getTimeMysqld(line string) time.Time {
	// "060102 15:04:05"
	matcher := regexp.MustCompile(`([0-9]{6} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	matches := matcher.FindStringSubmatch(line)
	t, err := time.Parse(timeFormatMysqld, matches[1])

	if err != nil {
		fmt.Println("Oops")
	}

	return t
}

func scanLines(scanner *bufio.Scanner, count int) []string {
	var lines []string
	for {
		lines = append(lines, scanner.Text())
		count--
		if count == 0 {
			return lines
		}
		scanner.Scan()
	}
}

func getEventsFromNode(node string, filePath string) []Event {
	//fmt.Printf("Getting events from %s\n", node)
	var events []Event

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		for _, eventMatcher := range eventMatchers {
			if eventMatcher.Match(scanner.Text()) {
				event := eventMatcher.Get(scanner)
				event.Node = node
				events = append(events, event)
			}
		}
	}

	return events
}

func renderHTML(timeline []Event) string {
	html := ""
	t, err := template.New("foo").ParseFiles("tmpl/timeline.html") // Parse template file.
	if err != nil {
		panic(err)
	}

	type renderData struct {
		Timeline []Event
	}

	data := renderData{
		timeline,
	}

	var doc bytes.Buffer
	t.ExecuteTemplate(&doc, "Timeline", data)
	html = doc.String()
	return html
}

func parseArgs() []string {
	files := os.Args[1:]
	return files
}

func main() {

	var files = parseArgs()

	var timeline []Event

	for i, filePath := range files {
		node := fmt.Sprintf("node%d", i)
		timeline = append(timeline, getEventsFromNode(node, filePath)...)
	}

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Datetime.Before(timeline[j].Datetime)
	})

	html := renderHTML(timeline)

	fmt.Println(html)

	/*
		for _, event := range timeline {
			header := ""
			switch event.Node {
			case "node 0":
				header = printBlue(fmt.Sprintf("%s %s", event.Node, event.Datetime))
			case "node 1":
				header = printMagenta(fmt.Sprintf("%s %s", event.Node, event.Datetime))
			case "node 2":
				header = printCyan(fmt.Sprintf("%s %s", event.Node, event.Datetime))
			}

			fmt.Printf("%s %s\n",
				header,
				event.Message,
			)
		}
	*/
}
