package dbusutil_test

import (
	"errors"
	"testing"

	"github.com/NordSecurity/nordvpn-linux/sysinfo/dbusutil"
	"github.com/NordSecurity/nordvpn-linux/test/category"
	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

type mockDBusClient struct {
	mockResponse dbus.Variant
	mockError    error
}

func (m *mockDBusClient) GetProperty(name string) (dbus.Variant, error) {
	if m.mockError != nil {
		return dbus.Variant{}, m.mockError
	}
	return m.mockResponse, nil
}

func Test_GetStringProperty_Success(t *testing.T) {
	category.Set(t, category.Unit)

	client := &mockDBusClient{
		mockResponse: dbus.MakeVariant("hello"),
	}
	result, err := dbusutil.GetStringProperty(client, "SomeProp")
	assert.NoError(t, err)
	assert.Equal(t, "hello", result)
}

func Test_GetStringProperty_InvalidType(t *testing.T) {
	category.Set(t, category.Unit)

	client := &mockDBusClient{
		mockResponse: dbus.MakeVariant(1234),
	}
	result, err := dbusutil.GetStringProperty(client, "SomeProp")
	assert.Error(t, err)
	assert.Empty(t, result)
}

func Test_GetStringProperty_ErrorFromClient(t *testing.T) {
	category.Set(t, category.Unit)

	client := &mockDBusClient{
		mockError: errors.New("DBus failure"),
	}
	result, err := dbusutil.GetStringProperty(client, "SomeProp")
	assert.Error(t, err)
	assert.Empty(t, result)
}

func Test_GetStringProperty_NilClient(t *testing.T) {
	category.Set(t, category.Unit)

	result, err := dbusutil.GetStringProperty(nil, "AnyProp")
	assert.Error(t, err)
	assert.Empty(t, result)
}

func Test_NewPropertyClient_NilClient(t *testing.T) {
	category.Set(t, category.Unit)

	client := dbusutil.NewPropertyClient(nil, "Service", "AnyProp")
	assert.Nil(t, client)
}

func Test_NewPropertyClient_DummyClient(t *testing.T) {
	category.Set(t, category.Unit)

	client := dbusutil.NewPropertyClient(&dbus.Conn{}, "Service", "AnyProp")
	assert.NotNil(t, client)
}
