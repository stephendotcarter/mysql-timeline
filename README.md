# mysql-timeline
Parse and format logs from a MySQL Galera cluster

Details
-
The tool parses known log lines (that I understand!) and generates a consolidated timeline of the events that happened on a cluster.

You still need to figure out what actually happened on the cluster but this is great to get a highlevel overview before digging deeper in to the logs.

Usage
-
1. Generate the timeline:
   - `mysql-timeline NODE0_LOG NODE1_LOG NODE2_LOG > timeline.html`
   - The tool expects 3 log files corresponding to MySQL node 0, 1 and 2.
2. Open `timeline.html` in your favourite browser.
3. The columns correspond to the nodes from left to right.
