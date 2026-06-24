package policy

import "encoding/json"

// Marshal serializes a body map back to JSON.
func Marshal(body map[string]interface{}) ([]byte, error) {
	return json.Marshal(body)
}
