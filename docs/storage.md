Inga har markerats

Fortsätt till innehåll
Använda Tenforward e-post med skärmläsningsprogram
in:sent
Aktivera skrivbordsaviseringar för Tenforward e-post.
OK  Nej tack

Konversationer

Programpolicy
Tillhandahålls av Google
Senaste kontoaktivitet: för 1 dag sedan
Information
leasing.avbetalning@handelsbanken.se
# Go53 DNS Data Storage Design

## 1. In-Memory Data Structure

- Each DNS **zone** (e.g. `"example.com."`) is a key in a `map`.
- Each zone value is a map of **record types** (`"A"`, `"MX"`, `"SOA"`, `"NS"`, etc).
- Each record type is a map (or array) of **record names** to their data struct.

**Go structure:**
```go
map[string]map[string]map[string]any
// zone      // type      // record name -> struct
```

**Example (JSON):**
```json
{
  "A": {
    "www.example.com.": { "name": "www.example.com.", "ip": "192.0.2.5", "ttl": 3600 }
  },
  "SOA": {
    "example.com.": {
      "name": "example.com.",
      "ns": "ns1.example.com.",
      "mbox": "admin.example.com.",
      "serial": 2024060101,
      "refresh": 3600,
      "retry": 600,
      "expire": 86400,
      "minttl": 3600,
      "ttl": 3600
    }
  },
  "MX": {
    "example.com.": {
      "name": "example.com.",
      "preference": 10,
      "mx": "mx1.example.com.",
      "ttl": 3600
    }
  },
  "NS": {
    "example.com.": [
      { "name": "example.com.", "ns": "ns1.example.com.", "ttl": 3600 },
      { "name": "example.com.", "ns": "ns2.example.com.", "ttl": 3600 }
    ]
  }
}
```

## 2. Backend: BadgerDB Key-Value Storage

- **Key:** zone name (e.g., `"example.com."`)
- **Value:** full JSON serialization of the zone’s records as above

### Write Flow
- On record add/delete/update:
    1. Update in-memory `cache[zone]`
    2. Marshal `cache[zone]` as JSON
    3. `db.Set(zoneName, jsonBlob)`

### Read Flow
- At startup or reload:
    1. For each key (zone) in BadgerDB:
    2. Read value
    3. Unmarshal JSON into `cache[zone]`

## 3. Backend: PostgreSQL Schema

For more advanced backends, use normalized tables:

### Zones Table
```sql
CREATE TABLE zones (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
```
### Records Table
```sql
CREATE TABLE records (
    id SERIAL PRIMARY KEY,
    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    ttl INTEGER,
    data JSONB NOT NULL
);
```

### Minimal Migration Example
```sql
-- go53_dns_schema.sql

CREATE TABLE zones (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE records (
    id SERIAL PRIMARY KEY,
    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    ttl INTEGER,
    data JSONB NOT NULL
);

CREATE INDEX idx_records_zone_type ON records(zone_id, type);
CREATE INDEX idx_records_name ON records(name);
```

## 4. Loading/Saving Data

- **In-memory**: Data is loaded into the `cache` map on startup or after modification.
- **BadgerDB**: Zones are persisted as full JSON blobs keyed by zone name.
- **PostgreSQL**: Each record is a row in `records`, with structured data in JSONB; lookup by zone, type, and name is fast and indexed.

## 5. Example Insert (PostgreSQL)

```sql
INSERT INTO zones (name) VALUES ('example.com.') RETURNING id;
-- Suppose id=1
INSERT INTO records (zone_id, name, type, ttl, data)
VALUES
  (1, 'www.example.com.', 'A', 3600, '{"ip": "192.0.2.5"}'),
  (1, 'example.com.', 'SOA', 3600, '{"ns": "ns1.example.com.", "mbox": "admin.example.com.", "serial": 2024060101, "refresh": 3600, "retry": 600, "expire": 86400, "minttl": 3600}')
;
```

## 6. Summary

- **In memory**:
    - `map[zone] = map[type] = map[name] = record`
    - JSON serializable; easy to persist/load
- **BadgerDB**:
    - Key = zone name, Value = full zone record JSON
- **PostgreSQL**:
    - `zones` and `records` tables, with all record data as JSONB
      go53_dns_storage_design.md
      Visar go53_dns_storage_design.md.