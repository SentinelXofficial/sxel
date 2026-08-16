package modules

import "strings"

func fingerprintDBMS(body string) string {
	low := strings.ToLower(body)
	switch {
	case strings.Contains(low, "you have an error in your sql syntax"),
		strings.Contains(low, "warning: mysql"),
		strings.Contains(low, "mysql_fetch"),
		strings.Contains(low, "mysqli"),
		strings.Contains(low, "com.mysql.jdbc"),
		strings.Contains(low, "mysql error"):
		return "mysql"
	case strings.Contains(low, "warning: pg_"),
		strings.Contains(low, "pg_query"),
		strings.Contains(low, "pg_exec"),
		strings.Contains(low, "org.postgresql"),
		strings.Contains(low, "npgsql"),
		strings.Contains(low, "postgresql query failed"):
		return "postgresql"
	case strings.Contains(low, "unclosed quotation mark after the character string"),
		strings.Contains(low, "microsoft ole db provider for sql server"),
		strings.Contains(low, "odbc sql server driver"),
		strings.Contains(low, "invalid object name"):
		return "mssql"
	case strings.Contains(low, "ora-017"),
		strings.Contains(low, "ora-009"),
		strings.Contains(low, "ora-000"):
		return "oracle"
	case strings.Contains(low, "sqlite_exec"),
		strings.Contains(low, "sqlite3::"),
		strings.Contains(low, "sqlite3."),
		strings.Contains(low, "sqlite_master"):
		return "sqlite"
	case strings.Contains(low, "java.sql"),
		strings.Contains(low, "jdbc:mysql"),
		strings.Contains(low, "jdbc:postgresql"),
		strings.Contains(low, "jdbc:oracle"):
		return "java-jdbc"
	}
	return ""
}

func dbmsLabel(body string) string {
	if db := fingerprintDBMS(body); db != "" {
		return " [" + db + "]"
	}
	return ""
}
