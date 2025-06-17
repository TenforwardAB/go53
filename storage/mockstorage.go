package storage

type MockStorage struct {
	Zones  map[string][]byte
	Tables map[string]map[string][]byte
}

func (m *MockStorage) Init() error {
	if m.Zones == nil {
		m.Zones = make(map[string][]byte)
	}
	if m.Tables == nil {
		m.Tables = make(map[string]map[string][]byte)
	}
	return nil
}

func (m *MockStorage) SaveZone(name string, data []byte) error {
	m.Zones[name] = data
	return nil
}

func (m *MockStorage) LoadZone(name string) ([]byte, error) {
	if data, ok := m.Zones[name]; ok {
		return data, nil
	}
	return nil, nil
}

func (m *MockStorage) DeleteZone(name string) error {
	delete(m.Zones, name)
	return nil
}

func (m *MockStorage) ListZones() ([]string, error) {
	keys := make([]string, 0, len(m.Zones))
	for k := range m.Zones {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *MockStorage) LoadAllZones() (map[string][]byte, error) {
	return m.Zones, nil
}

func (m *MockStorage) LoadTable(table string) (map[string][]byte, error) {
	if data, ok := m.Tables[table]; ok {
		return data, nil
	}
	return map[string][]byte{}, nil
}

func (m *MockStorage) SaveTable(table string, key string, value []byte) error {
	if _, ok := m.Tables[table]; !ok {
		m.Tables[table] = make(map[string][]byte)
	}
	m.Tables[table][key] = value
	return nil
}
