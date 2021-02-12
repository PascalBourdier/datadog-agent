// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package types

import (
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
)

// RunnerStatus holds the status report from the node-agent
type RunnerStatus struct {
	LastChange int64 `json:"last_change"`
}

// StatusResponse holds the DCA response for a status report
type StatusResponse struct {
	IsUpToDate bool `json:"isuptodate"`
}

// RebalanceResponse holds the DCA response for a rebalancing request
type RebalanceResponse struct {
	CheckID     string `json:"check_id"`
	CheckWeight int    `json:"check_weight"`

	SourceRunnerID string `json:"source_runner_id"`
	SourceDiff     int    `json:"source_diff"`

	DestRunnerID string `json:"dest_runner_id"`
	DestDiff     int    `json:"dest_diff"`
}

// ConfigResponse holds the DCA response for a config query
type ConfigResponse struct {
	LastChange int64                `json:"last_change"`
	Configs    []integration.Config `json:"configs"`
}

// StateResponse holds the DCA response for a dispatching state query
type StateResponse struct {
	NotRunning string                `json:"not_running"` // Reason why not running, empty if leading
	Warmup     bool                  `json:"warmup"`
	Runners    []StateRunnerResponse `json:"runners"`
	Dangling   []integration.Config  `json:"dangling"`
}

// StateRunnerResponse is a chunk of StateResponse
type StateRunnerResponse struct {
	Name    string               `json:"name"`
	Configs []integration.Config `json:"configs"`
}

// Stats holds statistics for the agent status command
type Stats struct {
	// Following
	Follower bool
	LeaderIP string

	// Leading
	Leader          bool
	Active          bool
	RunnerCount     int
	ActiveConfigs   int
	DanglingConfigs int
	TotalConfigs    int
}

// LeaderIPCallback describes the leader-election method we
// need and allows to inject a custom one for tests
type LeaderIPCallback func() (string, error)

// CLCRunnersStats is used to unmarshall the CLC Runners stats payload
type CLCRunnersStats map[string]CLCRunnerStats

// CLCRunnerStats is used to unmarshall the stats of each CLC Runner
type CLCRunnerStats struct {
	AverageExecutionTime int  `json:"AverageExecutionTime"`
	MetricSamples        int  `json:"MetricSamples"`
	IsClusterCheck       bool `json:"IsClusterCheck"`
	LastExecFailed       bool `json:"LastExecFailed"`
}
