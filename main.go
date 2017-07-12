package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
)

// Event is an interesting event that occurred in MySQL logs
//   - When it happened
//   - Which node in the cluster
//   - User friendly message
//   - Raw log lines
type Event struct {
	Datetime      time.Time
	GlobalOrderID int
	Node          int
	Message       string
	Raw           string
}

// EventMatcher represents whats needed to find an event MySQL logs
//   - Description of event
//   - Function to match the event signature
//   - Function to convert the raw text to an event
type EventMatcher struct {
	Description string
	Signature   string
	Get         func(*bufio.Scanner) *Event
}

func NewEvent(eventTime time.Time, node int, message string, raw []string) *Event {
	globalOrderID++

	return &Event{
		eventTime,
		globalOrderID,
		node,
		message,
		strings.Join(raw[:], "\n"),
	}

}

func (e *EventMatcher) Match(line string) bool {
	return strings.Contains(line, e.Signature)
}

func printDanger(line string) string {
	return fmt.Sprintf("<danger>%s</danger>", line)
}

func printSuccess(line string) string {
	return fmt.Sprintf("<success>%s</success>", line)
}

var (
	globalOrderID = 0 // Used to ensure timestamps within same second are ordered correctly

	timeFormatDefault  = "2006-01-02 15:04:05"
	timeFormatWsrepSst = "20060102 15:04:05"
	timeFormatMysqld   = "060102 15:04:05"
	timeFormatYMDHMS   = "20060102150405"

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

	tmplTimeline = `{{define "Timeline"}}
<style>
body{ font-family: Courier New, Courier, monospace; }
td { font-size: 10pt; white-space: pre-wrap; vertical-align: top; }
.color-node0 { background: #D9B3FF; }
.color-node1 { background: #B3B3FF; }
.color-node2 { background: #B3D9FF; }
success { color: #5cb85c; font-weight: bold; }
danger { color: #d9534f; font-weight: bold; }
</style>
<table border="1">
<thead>
<th>Node</th><th>Date</th><th>Message</th>
</thead>
{{ range $event := .Timeline }}<tr class="color-{{ $event.Node }}"><td>{{ $event.Node }}</td><td>{{ $event.Datetime }}</td><td>{{ $event.Message }}</td></tr>
{{ end }}
</table>
{{end}}`

	// Event matchers for all know events
	eventMatchers = []EventMatcher{
		EventMatcher{
			"Node is changing state",
			"WSREP: Shifting",
			func(scanner *bufio.Scanner) *Event {
				// 2015-10-28 16:36:52 10144 [Note] WSREP: Shifting PRIMARY -> JOINER (TO: 31389)
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				matcher := regexp.MustCompile(` Shifting (.*) -> (.*) \(TO: ([0-9]*\))`)
				matches := matcher.FindStringSubmatch(lines[0])

				message := fmt.Sprintf("%s => ", matches[1])

				if shiftState[matches[1]] > shiftState[matches[2]] {
					message = message + printDanger(matches[2])
				} else {
					message = message + printSuccess(matches[2])
				}

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Quorum results",
			"WSREP: Quorum results:",
			func(scanner *bufio.Scanner) *Event {
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

				componentString := component
				if component == "PRIMARY" {
					componentString = printSuccess(componentString)
				} else {
					componentString = printDanger(componentString)
				}

				membersString := fmt.Sprintf("%s/%s", membersJoined, membersTotal)
				if membersJoined == membersTotal {
					membersString = printSuccess(membersString)
				} else {
					membersString = printDanger(membersString)
				}

				message := fmt.Sprintf("Component: %s, Members: %s", componentString, membersString)

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"State Transfer Required",
			"WSREP: State transfer required:",
			func(scanner *bufio.Scanner) *Event {
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
					localStateString = printDanger(localStateString)
				} else {
					localStateString = printSuccess(localStateString)
				}

				message := fmt.Sprintf("Group: %s\nLocal: %s", groupStateString, localStateString)

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"WSREP recovered position",
			"WSREP: Recovered position ",
			func(scanner *bufio.Scanner) *Event {
				// 2017-06-14 14:02:28 139993574066048 [Note] WSREP: Recovered position f3d1aa70-31a3-11e7-908c-f7a5ad9e63b1:40847697
				lines := scanLines(scanner, 1)
				eventTime := getTimeMysqld(lines[0])

				matcher := regexp.MustCompile(`Recovered position (.*):(.*)`)
				matches := matcher.FindStringSubmatch(lines[0])
				uuid := matches[1]
				seqno := matches[2]

				recoveredString := fmt.Sprintf("%s:%s", uuid, seqno)
				if seqno == "-1" {
					recoveredString = printDanger(recoveredString)
				} else {
					recoveredString = printSuccess(recoveredString)
				}

				message := fmt.Sprintf("Recovered position: %s", recoveredString)

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Interruptor",
			"SST disabled due to danger of data loss",
			func(scanner *bufio.Scanner) *Event {
				// WSREP_SST: [ERROR] ############################################################################## (20170506 15:14:06.901)
				// WSREP_SST: [ERROR] SST disabled due to danger of data loss. Verify data and bootstrap the cluster (20170506 15:14:06.902)
				// WSREP_SST: [ERROR] ############################################################################## (20170506 15:14:06.904)
				lines := scanLines(scanner, 1)
				eventTime := getTimeWsrepSst(lines[0])

				message := printDanger(`++++++++++ Interruptor ++++++++++`)

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"MySQL ended",
			" from pid file ",
			func(scanner *bufio.Scanner) *Event {
				// 170505 14:35:47 mysqld_safe mysqld from pid file /tmp/tmp-mysql.pid ended
				lines := scanLines(scanner, 1)
				eventTime := getTimeMysqld(lines[0])

				message := printDanger("PID ended")

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"MySQL normal shutdown",
			"mysqld: Normal shutdown",
			func(scanner *bufio.Scanner) *Event {
				// 2017-05-05 14:35:45 139716968405760 [Note] /var/vcap/packages/mariadb/bin/mysqld: Normal shutdown
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				message := printSuccess("Normal Shutdown")

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"MySQL startup",
			"starting as process",
			func(scanner *bufio.Scanner) *Event {
				// 2017-05-06 16:53:13 140445682804608 [Note] /var/vcap/packages/mariadb/bin/mysqld (mysqld 10.1.18-MariaDB) starting as process 24588 ...
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				message := "MySQL startup"

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"InnoDB shutdown",
			"InnoDB: Starting shutdown...",
			func(scanner *bufio.Scanner) *Event {
				// 2017-05-06 16:53:08 140348661906176 [Note] InnoDB: Starting shutdown...
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				message := "InnoDB shutdown"

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"InnoDB shutdown complete",
			"mysqld: Shutdown complete",
			func(scanner *bufio.Scanner) *Event {
				// 2017-05-05 14:35:47 139716968405760 [Note] /var/vcap/packages/mariadb/bin/mysqld: Shutdown complete
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				message := "MySQL shutdown complete"

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Primary not possible",
			"WSREP: no nodes coming from prim view",
			func(scanner *bufio.Scanner) *Event {
				// 2017-05-05  6:50:37 140137601001344 [Warning] WSREP: no nodes coming from prim view, prim not possible
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				message := "Primary not possible"

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Cluster View",
			"WSREP: view(",
			func(scanner *bufio.Scanner) *Event {
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

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"xtrabackup",
			"WSREP: Running: ",
			func(scanner *bufio.Scanner) *Event {
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

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"WSREP Transaction ID",
			"WSREP: Set WSREPXid for InnoDB: ",
			func(scanner *bufio.Scanner) *Event {
				// 2017-06-22 16:50:12 140484737350400 [Note] WSREP: Set WSREPXid for InnoDB:  13f831b9-2d93-11e6-9385-a607db88d15b:36559417
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				matcher := regexp.MustCompile(`Set WSREPXid for InnoDB:  (.*)`)
				matches := matcher.FindStringSubmatch(lines[0])
				xid := matches[1]

				message := fmt.Sprintf("WSREPXid = %s", xid)

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Node consistency compromized",
			"WSREP: Node consistency compromized",
			func(scanner *bufio.Scanner) *Event {
				// 2017-06-14  8:01:24 140433225386752 [ERROR] WSREP: Node consistency compromized, aborting...
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				message := printDanger("Node consistency compromized")

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Slave SQL Error",
			" Slave SQL: Error",
			func(scanner *bufio.Scanner) *Event {
				// 2017-03-24 10:25:00 140656657582848 [ERROR] Slave SQL: Error 'Table 'cf_f08ec188_bbf7_4a27_a001_97749f736849.COL1' doesn't exist' on query. Default database: 'cf_f08ec188_bbf7_4a27_a001_97749f736849'. Query: 'alter table COL1 drop foreign key FK8kw677hwx7cgwi4g1r6c56398', Internal MariaDB error code: 1146
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				//matcher := regexp.MustCompile(`Slave SQL: (Error.*), Internal MariaDB error code: (.*)`)
				//matches := matcher.FindStringSubmatch(lines[0])
				//error := matches[1]
				//code := matches[2]

				//message := fmt.Sprintf("%s\n%s", error, code)
				message := printDanger("Slave SQL Error")

				return NewEvent(eventTime, 0, message, lines)
			},
		},
		EventMatcher{
			"Fatal Error",
			" Fatal error:",
			func(scanner *bufio.Scanner) *Event {
				// 2017-05-06 14:51:43 139983057127296 [ERROR] Fatal error: Can't open and lock privilege tables: Table 'mysql.user' doesn't exist
				lines := scanLines(scanner, 1)
				eventTime := getTimeDefault(lines[0])

				matcher := regexp.MustCompile(` Fatal error: (.*)`)
				matches := matcher.FindStringSubmatch(lines[0])
				fatalError := matches[1]

				message := fmt.Sprintf(printDanger("Fatal Error: %s"), fatalError)

				return NewEvent(eventTime, 0, message, lines)
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

func getEventsFromNode(node int, filePath string) []*Event {
	var events []*Event

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
				break
			}
		}
	}

	return events
}

func renderHTML(timeline []*Event) string {
	html := ""
	t, err := template.New("foo").Parse(tmplTimeline)
	if err != nil {
		panic(err)
	}

	type renderData struct {
		Timeline []*Event
	}

	data := renderData{
		timeline,
	}

	var doc bytes.Buffer
	t.ExecuteTemplate(&doc, "Timeline", data)
	html = doc.String()
	return html
}

func renderHTMLCols(timeline []*Event) string {

	var timelineCols = make(map[string][][]*Event)

	var tmplTimelineCols = `{{define "Timeline"}}
<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
<style>
body{ font-family: Courier New, Courier, monospace; }
td { font-size: 10pt; white-space: pre-wrap; vertical-align: top; }
.nowrap { white-space: nowrap; }
success { color: #5cb85c; font-weight: bold; }
danger { color: #d9534f; font-weight: bold; }
</style>
<table class="table table-bordered table-condensed">
<!--<thead>
<th>Node</th><th>Date</th><th>Message</th>
</thead>-->
{{ range $time, $nodes := .Timeline }}
<tr>
	<td class="nowrap">{{ $time }}</td>
	{{ range $node := $nodes }}
	<td>{{ range $event := $node }}{{ $event.Message }}
{{ end }}</td>
	{{ end }}
</tr>
{{ end }}
</table>
{{end}}`

	for _, event := range timeline {
		//fmt.Println(event)
		timeString := event.Datetime.Format("2006-01-02 15:04:05")
		if _, ok := timelineCols[timeString]; !ok {
			timelineCols[timeString] = make([][]*Event, 3)
			timelineCols[timeString][0] = make([]*Event, 0)
			timelineCols[timeString][1] = make([]*Event, 0)
			timelineCols[timeString][2] = make([]*Event, 0)
		}

		timelineCols[timeString][event.Node] = append(timelineCols[timeString][event.Node], event)
	}

	t, err := template.New("foo").Parse(tmplTimelineCols)
	if err != nil {
		panic(err)
	}

	type renderData struct {
		Timeline map[string][][]*Event
	}

	data := renderData{
		timelineCols,
	}

	var doc bytes.Buffer
	t.ExecuteTemplate(&doc, "Timeline", data)
	html := doc.String()
	return html
}

func parseArgs() []string {
	files := os.Args[1:]
	return files
}

func main() {

	var files = parseArgs()

	var timeline []*Event

	for i, filePath := range files {
		node := i
		os.Stderr.WriteString("Parsing node\n")
		timeline = append(timeline, getEventsFromNode(node, filePath)...)
	}

	os.Stderr.WriteString("Sorting\n")
	sort.Slice(timeline, func(i, j int) bool {
		if timeline[i].Datetime.Equal(timeline[j].Datetime) {
			return timeline[i].GlobalOrderID < timeline[j].GlobalOrderID
		}
		return timeline[i].Datetime.Before(timeline[j].Datetime)
	})

	os.Stderr.WriteString("Rendering\n")
	html := renderHTMLCols(timeline)

	os.Stderr.WriteString("Printing\n")
	fmt.Println(html)
}
