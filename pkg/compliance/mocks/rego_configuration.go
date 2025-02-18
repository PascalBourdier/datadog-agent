// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package mocks

import (
	env "github.com/DataDog/datadog-agent/pkg/compliance/checks/env"
	mock "github.com/stretchr/testify/mock"
)

// RegoConfiguration is an autogenerated mock type for the RegoConfiguration type
type RegoConfiguration struct {
	mock.Mock
}

// DumpInputPath provides a mock function with given fields:
func (_m *RegoConfiguration) DumpInputPath() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// ProvidedInput provides a mock function with given fields: ruleID
func (_m *RegoConfiguration) ProvidedInput(ruleID string) env.ProvidedInputMap {
	ret := _m.Called(ruleID)

	var r0 env.ProvidedInputMap
	if rf, ok := ret.Get(0).(func(string) env.ProvidedInputMap); ok {
		r0 = rf(ruleID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(env.ProvidedInputMap)
		}
	}

	return r0
}
