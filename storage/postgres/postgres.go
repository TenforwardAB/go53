package postgres

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type PostgresStorage struct {
	db *sql.DB
}

func NewPostgresStorage() *PostgresStorage {
	return &PostgresStorage{}
}

func (p *PostgresStorage) Init() error {
	dsn := "host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	p.db = db
	query := `
		CREATE TABLE IF NOT EXISTS zones (
			name TEXT PRIMARY KEY,
			data BYTEA
		)`
	_, err = p.db.Exec(query)
	return err
}

func (p *PostgresStorage) SaveZone(name string, data []byte) error {
	_, err := p.db.Exec(`
		INSERT INTO zones (name, data)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data`, name, data)
	return err
}

func (p *PostgresStorage) LoadZone(name string) ([]byte, error) {
	var data []byte
	err := p.db.QueryRow(`SELECT data FROM zones WHERE name = $1`, name).Scan(&data)
	return data, err
}

func (p *PostgresStorage) DeleteZone(name string) error {
	_, err := p.db.Exec(`DELETE FROM zones WHERE name = $1`, name)
	return err
}

func (p *PostgresStorage) ListZones() ([]string, error) {
	rows, err := p.db.Query(`SELECT name FROM zones`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var zones []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		zones = append(zones, name)
	}
	return zones, nil
}
