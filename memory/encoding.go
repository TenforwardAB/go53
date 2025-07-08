package memory

import (
	"encoding/json"
	"github.com/TenforwardAB/slog"
)

func encodeZoneData(data map[string]map[string]any) ([]byte, error) {
	slog.Crazy("[encodeZoneData] Data for Encoding is: %v", data)
	return json.Marshal(data)
}

func decodeZoneData(raw []byte) (map[string]map[string]any, error) {
	var result map[string]map[string]any
	err := json.Unmarshal(raw, &result)
	return result, err
}
