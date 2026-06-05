package memory

import (
	"encoding/json"
	"fmt"
	"github.com/TenforwardAB/slog"
)

func encodeZoneData(data map[string]map[string]any) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = fmt.Errorf("failed to encode zone data: %v", r)
		}
	}()

	if data == nil {
		return nil, fmt.Errorf("cannot encode nil zone data")
	}
	slog.Crazy("[encodeZoneData] Data for Encoding is: %v", data)
	return json.Marshal(data)
}

func decodeZoneData(raw []byte) (map[string]map[string]any, error) {
	if len(raw) == 0 {
		return map[string]map[string]any{}, nil
	}
	var result map[string]map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result == nil {
		result = map[string]map[string]any{}
	}
	return result, nil
}
