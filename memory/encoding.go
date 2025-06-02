package memory

import (
	"encoding/json"
)

func encodeZoneData(data map[string]map[string]any) ([]byte, error) {
	return json.Marshal(data)
}

func decodeZoneData(raw []byte) (map[string]map[string]any, error) {
	var result map[string]map[string]any
	err := json.Unmarshal(raw, &result)
	return result, err
}
