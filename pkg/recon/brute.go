package recon

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var builtinWords = []string{
	"www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2", "ns3", "ns4",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2", "smtp2", "relay",
	"admin", "administrator", "adm", "api", "apiv2", "apiv1", "dev", "devel", "development",
	"stage", "staging", "test", "testing", "qa", "uat", "pre", "preprod", "prod", "production",
	"app", "apps", "app1", "app2", "app3", "application", "blog", "cdn", "cdn1", "cdn2",
	"cloud", "dashboard", "demo", "docs", "documentation", "download", "downloads",
	"git", "gitlab", "github", "gitea", "help", "helpdesk", "internal", "intranet",
	"jenkins", "jira", "kibana", "grafana", "prometheus", "sentry", "sonar", "sonarqube",
	"login", "signin", "signup", "register", "auth", "sso", "id", "oauth", "identity",
	"m", "mobile", "mobi", "manage", "manager", "management", "monitor", "monitoring",
	"news", "origin", "originserver", "panel", "cpanel", "whm", "plesk", "partner",
	"partners", "pay", "payment", "payments", "billing", "checkout", "paypal",
	"portal", "remote", "sandbox", "secure", "server", "servers", "shop", "store",
	"static", "stats", "statistics", "status", "support", "survey", "syslog",
	"uat", "upload", "uploads", "vpn", "web", "webmail", "wiki", "ws", "www2", "www3",
	"beta", "alpha", "gamma", "gateway", "gw", "lb", "proxy", "cache", "edge",
	"assets", "images", "img", "media", "video", "search", "data", "db", "database",
	"db1", "db2", "db3", "sql", "mysql", "redis", "mongo", "mongodb", "kafka",
	"backup", "backups", "bak", "staging2", "stage2", "dev2", "test2",
	"cms", "crm", "erp", "hr", "finance", "accounting", "analytics", "reporting",
	"ip", "ips", "ipsec", "ldap", "ad", "dc1", "dc2", "ntp", "sip", "voip", "asterisk",
	"firewall", "fw", "router", "switch", "printer", "print", "scanner", "scan",
	"noc", "ops", "opsworks", "tools", "tool", "utility", "util", "misc",
	"client", "clients", "customer", "customers", "user", "users", "member", "members",
	"public", "pub", "private", "internal2", "ext", "external", "extranet", "dns3",
	"lab", "labs", "research", "knowledge", "kb", "faq", "feedback", "forum", "forums",
	"chat", "livechat", "support2", "ticket", "tickets", "servicedesk", "desk",
	"ecommerce", "shop2", "market", "marketplace", "auction", "ad", "ads", "adserver",
	"newsletter", "mailer", "list", "lists", "bulk", "api2", "rest", "graphql", "grpc",
	"hq", "office", "sf", "salesforce", "workday", "sap", "oracle", "sap01",
	"tst", "qa1", "qa2", "stage1", "pre1", "prod1", "prod2", "p01", "p02",
	"01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
	"11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
	"v2", "v3", "v4", "api3", "api4", "gate", "openapi", "publicapi", "privateapi",
	"old", "legacy", "archive", "archives", "snap", "snapshot", "snapshots", "nightly",
	"metrics", "metric", "logs", "log", "logging", "traces", "trace", "alerts", "alert",
	"dash", "board", "reports", "report", "bi", "datastudio", "looker", "superset",
	"ws1", "wss", "websocket", "socket", "sockets", "stream", "streams", "live",
	"event", "events", "webinar", "meeting", "meetings", "meet", "zoom", "teams",
	"storage", "store2", "files", "file", "share", "shares", "drive", "box", "dropbox",
	"sync", "syncing", "syncs", "webdav", "dav", "cal", "calendar", "mail2", "owa",
	"autodiscover", "autodiscover2", "lync", "lyncdiscover", "skype", "skypeforbusiness",
	"mdm", "wsus", "sccm", "scom", "vcenter", "vmware", "esxi", "esx", "hyperv",
	"cacti", "nagios", "zabbix", "munin", "ganglia", "collectd", "cacti2",
	"puppet", "chef", "ansible", "salt", "saltmaster", "docker", "registry", "k8s",
	"kube", "kubernetes", "rancher", "openshift", "harbor", "nexus", "artifactory",
	"maven", "npm", "pypi", "pypi2", "registry2", "gitlab-ci", "ci", "cd", "cicd",
	"build", "builder", "builds", "runner", "runners", "worker", "workers", "agent",
	"agents", "bot", "bots", "webhook", "webhooks", "hook", "hooks", "callback",
	"notify", "notifications", "push", "pusher", "sms", "sms-gateway", "voice",
	"phone", "tel", "pbx", "sip2", "sip3", "rtp", "turn", "stun", "coturn",
	"geo", "geoip", "location", "map", "maps", "gis", "tile", "tiles",
	"photos", "photo", "pics", "images2", "img2", "assets2", "static2", "static3",
	"js", "css", "fonts", "font", "webfont", "icons", "icon", "favicon",
	"amp", "cdn2", "cdn3", "edge2", "edge3", "pop", "pop2", "edge-cdn",
	"api-gateway", "gateway2", "gw2", "vpn2", "remote2", "access", "access2",
	"sslvpn", "ssl", "tls", "cert", "certs", "pki", "ca", "crl", "ocsp",
	"ntp2", "time", "timesync", "clock", "chrony", "nts", "broadcast", "bcast",
	"radio", "radio2", "stream2", "live2", "tv", "iptv", "video2", "vod",
	"media2", "static4", "static5", "cdn4", "cdn5", "cache2", "cache3", "memcached",
	"elk", "elastic", "elasticsearch", "logstash", "kibana2", "filebeat", "metricbeat",
	"airflow", "spark", "hadoop", "hive", "presto", "trino", "flink", "kafka2", "zookeeper",
	"postgres", "postgresql", "pg", "pgsql", "mariadb", "mariadb2", "cassandra", "cass",
	"couchdb", "couch", "neo4j", "mssql", "mssql2", "sqlserver", "sql2012", "sql2014",
	"oracle2", "oradb", "oem", "oem2", "tns", "tnsnames", "plsql", "sqlplus",
	"wildfly", "jboss", "tomcat", "tomcat2", "tc", "websphere", "was", "wasadmin",
	"glassfish", "payara", "jetty", "undertow", "weblogic", "wls", "wls2",
	"iis", "www-01", "www-02", "web01", "web02", "web03", "web04", "web05",
	"app01", "app02", "app03", "api01", "api02", "db01", "db02", "srv01", "srv02",
}

func BuiltinWordlist() []string {
	out := make([]string, len(builtinWords))
	copy(out, builtinWords)
	return out
}

func wildcardDNS(domain string) bool {
	return resolveHost("sxel-wildcard-check-"+randHex(8)+"."+domain, 2*time.Second)
}

func resolveHost(host string, timeout time.Duration) bool {
	addrs, err := net.LookupHost(host)
	if err == nil && len(addrs) > 0 {
		return true
	}
	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
		port := cc.Port
		if port == "" {
			port = "53"
		}
		servers = make([]string, 0, len(cc.Servers))
		for _, s := range cc.Servers {
			servers = append(servers, net.JoinHostPort(s, port))
		}
	}
	c := &dns.Client{Timeout: timeout}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeCNAME} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		for _, srv := range servers {
			r, _, err := c.Exchange(m, srv)
			if err == nil && r != nil && len(r.Answer) > 0 {
				return true
			}
		}
	}
	return false
}

var hexChars = "0123456789abcdef"

func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[time.Now().UnixNano()%16]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}

func BruteSubdomains(domain string, words []string, wildcard bool, concurrency int) []string {
	if concurrency <= 0 {
		concurrency = 50
	}
	seen := map[string]bool{}
	var mu sync.Mutex
	var found []string
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, w := range words {
		w = strings.TrimSpace(strings.ToLower(w))
		if w == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := w + "." + domain
			ok := resolveHost(host, 2*time.Second)
			if ok && wildcard {
				marker := "sxel-" + randHex(12) + "." + domain
				if resolveHost(marker, 2*time.Second) {
					ok = false
				}
			}
			if ok {
				mu.Lock()
				if !seen[host] {
					seen[host] = true
					found = append(found, host)
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return found
}
