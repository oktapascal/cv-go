package config

import (
	"database/sql"

	_ "github.com/denisenkom/go-mssqldb"
)

func Connect() (*sql.DB, error) {
	db, err := sql.Open("sqlserver", "sqlserver://sa:Saku3@ws1979Sql@52.220.100.190:8282?database=dbdev&connection+timeout=30")

	if err != nil {
		return nil, err
	}

	return db, nil
}
