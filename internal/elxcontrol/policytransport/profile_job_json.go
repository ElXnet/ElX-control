package policytransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// validateUniqueControlJobJSON rejects repeated fields before encoding/json
// performs its permissive case-insensitive struct field matching.
func validateUniqueControlJobJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := readUniqueControlJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("ambiguous or trailing Control job")
	}
	return nil
}

func readUniqueControlJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("non-string Control job field")
			}
			canonical := strings.ToLower(key)
			if seen[canonical] {
				return errors.New("duplicate Control job field")
			}
			seen[canonical] = true
			if err := readUniqueControlJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := readUniqueControlJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid Control job JSON delimiter")
	}
	end, err := decoder.Token()
	if err != nil || end != closing {
		return errors.New("unterminated Control job JSON")
	}
	return nil
}
