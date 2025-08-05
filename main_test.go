package main

import (
	
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToJson(t *testing.T) {
	// Test with a simple struct
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	s := TestStruct{Name: "test", Value: 123}
	jsonStr, err := toJson(s)
	assert.NoError(t, err)
	assert.Equal(t, "{\"name\":\"test\",\"value\":123}", jsonStr)

	// Test with a map
	m := map[string]string{"key": "value"}
	jsonStr, err = toJson(m)
	assert.NoError(t, err)
	assert.Equal(t, "{\"key\":\"value\"}", jsonStr)

	// Test with a slice
	slice := []int{1, 2, 3}
	jsonStr, err = toJson(slice)
	assert.NoError(t, err)
	assert.Equal(t, "[1,2,3]", jsonStr)

	// Test with nil
	jsonStr, err = toJson(nil)
	assert.NoError(t, err)
	assert.Equal(t, "null", jsonStr)
}

func TestHashPassword(t *testing.T) {
	password := "testpassword"
	hashedPassword, err := hashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)

	// Hashing the same password should produce a different hash due to salt
	hashedPassword2, err := hashPassword(password)
	assert.NoError(t, err)
	assert.NotEqual(t, hashedPassword, hashedPassword2)
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword"
	hashedPassword, _ := hashPassword(password)

	// Correct password
	assert.True(t, checkPasswordHash(password, hashedPassword))

	// Incorrect password
	assert.False(t, checkPasswordHash("wrongpassword", hashedPassword))

	// Empty password
	assert.False(t, checkPasswordHash("", hashedPassword))
}
