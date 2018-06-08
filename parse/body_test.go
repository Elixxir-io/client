package parse

import (
	"bytes"
	"testing"
)

func TestParse(t *testing.T) {
	body := []byte{0x80, 0x02, 0x89, 0x02, 0x03, 0x04}
	actual, err := Parse(body)
	expected := &TypedBody{}
	expected.Body = []byte{0x89, 0x02, 0x03, 0x04}
	expected.BodyType = 256

	if err != nil {
		t.Error(err.Error())
	}

	if actual.BodyType != expected.BodyType {
		t.Errorf("Body type didn't match. Expected: %v, actual: %v",
			expected.BodyType, actual.BodyType)
	} else if !bytes.Equal(actual.Body, expected.Body) {
		t.Errorf("Body didn't match. Expected: %v, actual: %v",
			expected.Body, actual.Body)
	}
}

func TestParseTypeTooLong(t *testing.T) {
	body := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x01, 0x02, 0x03, 0x04}
	_, err := Parse(body)

	if err == nil {
		t.Error("Didn't get an error from Parse(" +
			") when the body type was too long")
	}
}

func TestTypeAsBytes(t *testing.T) {
	expected := []byte{0x80, 0x02}
	actual := TypeAsBytes(256)
	if !bytes.Equal(expected, actual) {
		t.Errorf("Type magic number didn't match. Expected: %v, actual: %v",
			expected, actual)
	}
}
