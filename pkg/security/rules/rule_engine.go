// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package rules

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/DataDog/datadog-agent/pkg/security/secl/eval"
	"github.com/hashicorp/go-multierror"
)

type RuleEngine struct {
	logger    Logger
	opts      *Opts
	policy    *RuleSet
	profiles  []*RuleSet
	pool      *eval.ContextPool
	listeners []RuleEngineListener
	model     eval.Model
	eventCtor func() eval.Event
}

// RuleEngineListener describes the methods implemented by an object used to be
// notified of events on a rule engine.
type RuleEngineListener interface {
	RuleMatch(rule *Rule, event eval.Event)
	EventDiscarderFound(re *RuleEngine, event eval.Event, field eval.Field, eventType eval.EventType)
}

// Opts defines rules set options
type Opts struct {
	eval.Opts
	SupportedDiscarders map[eval.Field]bool
	ReservedRuleIDs     []RuleID
	EventTypeEnabled    map[eval.EventType]bool
	Logger              Logger
}

func (re *RuleEngine) GetFields(field string) {
}

func (re *RuleEngine) GetProfile(event eval.Event) *RuleSet {
	// TODO(lebauce): get correct profile
	if len(re.profiles) > 0 {
		return re.profiles[0]
	}
	return nil
}

// NotifyRuleMatch notifies all the rule engine listeners that an event matched a rule
func (re *RuleEngine) NotifyRuleMatch(rule *Rule, event eval.Event) {
	for _, listener := range re.listeners {
		listener.RuleMatch(rule, event)
	}
}

// NotifyDiscarderFound notifies all the rule engine listeners that a discarder was found for an event
func (re *RuleEngine) NotifyDiscarderFound(event eval.Event, field eval.Field, eventType eval.EventType) {
	for _, listener := range re.listeners {
		listener.EventDiscarderFound(re, event, field, eventType)
	}
}

// Evaluate the specified event against the set of rules
func (re *RuleEngine) Evaluate(event eval.Event) bool {
	ctx := re.pool.Get(event.GetPointer())
	defer re.pool.Put(ctx)

	bucket := RuleBucket{}
	eventType := event.GetType()

	profileMatch := true
	if profile := re.GetProfile(event); profile != nil {
		profileMatch = profile.Evaluate(ctx, event, func(rule *Rule, event eval.Event) {
			re.NotifyRuleMatch(rule, event)
		})

		if profileMatch {
			profileBucket := profile.GetBucket(eventType)
			bucket.fields = append(bucket.fields, profileBucket.fields...)
		}
	}

	policyMatch := re.policy.Evaluate(ctx, event, nil)
	if !policyMatch {
		if policyBucket := re.policy.GetBucket(eventType); policyBucket != nil {
			bucket.fields = append(bucket.fields, policyBucket.fields...)
		}
	}

	if profileMatch && !policyMatch {
		re.logger.Tracef("Looking for discarders for event of type `%s`", eventType)

		for _, field := range bucket.fields {
			if re.opts.SupportedDiscarders != nil {
				if _, exists := re.opts.SupportedDiscarders[field]; !exists {
					continue
				}
			}

			isDiscarder := true
			for _, rule := range bucket.rules {
				isTrue, err := rule.PartialEval(ctx, field)
				if err != nil || isTrue {
					isDiscarder = false
					break
				}
			}
			if isDiscarder {
				re.NotifyDiscarderFound(event, field, eventType)
			}
		}
	}

	return policyMatch || !profileMatch
}

func (re *RuleEngine) GetBucket(eventType eval.EventType) (*RuleBucket, bool) {
	bucket, exists := &RuleBucket{}, false

	if policyBucket := re.policy.GetBucket(eventType); policyBucket != nil {
		bucket.Merge(policyBucket)
		exists = true
	}

	for _, profile := range re.profiles {
		if profileBucket := profile.GetBucket(eventType); profileBucket != nil {
			bucket.Merge(profileBucket)
			exists = true
		}
	}

	return bucket, exists
}

// AddListener adds a listener on the rule engine
func (re *RuleEngine) AddListener(listener RuleEngineListener) {
	re.listeners = append(re.listeners, listener)
}

// GetApprovers returns all approvers
func (re *RuleEngine) GetApprovers(fieldCaps map[eval.EventType]FieldCapabilities) (map[eval.EventType]Approvers, error) {
	approvers := make(map[eval.EventType]Approvers)
	for _, eventType := range re.GetEventTypes() {
		caps, exists := fieldCaps[eventType]
		if !exists {
			continue
		}

		eventApprovers, err := re.GetEventApprovers(eventType, caps)
		if err != nil {
			continue
		}
		approvers[eventType] = eventApprovers
	}

	return approvers, nil
}

// GetEventTypes returns all the event types handled by the rule engine
func (re *RuleEngine) GetEventTypes() []eval.EventType {
	eventTypesMap := make(map[string]bool)
	for eventType := range re.policy.eventRuleBuckets {
		eventTypesMap[eventType] = true
	}

	for _, profile := range re.profiles {
		for eventType := range profile.eventRuleBuckets {
			eventTypesMap[eventType] = true
		}
	}

	i := 0
	eventTypes := make([]eval.EventType, len(eventTypesMap))
	for eventType := range eventTypesMap {
		eventTypes[i] = eventType
		i++
	}

	return eventTypes
}

// GetEventApprovers returns approvers for the given event type and the fields
func (re *RuleEngine) GetEventApprovers(eventType eval.EventType, fieldCaps FieldCapabilities) (Approvers, error) {
	event := re.eventCtor()

	for _, profile := range re.profiles {
		if profileBucket := profile.GetBucket(eventType); profileBucket != nil {
			return nil, nil
		}
	}

	policyBucket := re.policy.GetBucket(eventType)
	if policyBucket != nil {
		return policyBucket.GetApprovers(event, fieldCaps, true)
	}

	return nil, nil
}

// HasRulesForEventType returns if there is at least one rule for the given event type
func (re *RuleEngine) HasRulesForEventType(eventType eval.EventType) bool {
	if re.policy.HasRulesForEventType(eventType) {
		return true
	}

	for _, profile := range re.profiles {
		if profile.HasRulesForEventType(eventType) {
			return true
		}
	}

	return false
}

// IsDiscarder partially evaluates an Event against a field
func (re *RuleEngine) IsDiscarder(event eval.Event, field eval.Field) (bool, error) {
	eventType, err := event.GetFieldEventType(field)
	if err != nil {
		return false, err
	}

	bucket, exists := re.GetBucket(eventType)
	if !exists {
		return false, &ErrNoEventTypeBucket{EventType: eventType}
	}

	ctx := re.pool.Get(event.GetPointer())
	defer re.pool.Put(ctx)

	for _, rule := range bucket.rules {
		isTrue, err := rule.PartialEval(ctx, field)
		if err != nil || isTrue {
			return false, err
		}
	}
	return true, nil
}

func (re *RuleEngine) newRuleSet() *RuleSet {
	return NewRuleSet(re.model, re.eventCtor, re.opts)
}

func (re *RuleEngine) LoadProfiles(profilesDir string) error {
	var result *multierror.Error

	profileFiles, err := ioutil.ReadDir(profilesDir)
	if err != nil {
		return multierror.Append(result, ErrProfileLoad{Name: profilesDir, Err: err})
	}
	sort.Slice(profileFiles, func(i, j int) bool { return profileFiles[i].Name() < profileFiles[j].Name() })

	// Load and parse profiles
	for _, profilePath := range profileFiles {
		filename := profilePath.Name()
		ruleSet := re.newRuleSet()

		// profile path extension check
		if filepath.Ext(filename) != ".profile" {
			ruleSet.logger.Debugf("ignoring file `%s` wrong extension `%s`", profilePath.Name(), filepath.Ext(filename))
			continue
		}

		// Open profile path
		f, err := os.Open(filepath.Join(profilesDir, filename))
		if err != nil {
			result = multierror.Append(result, &ErrPolicyLoad{Name: filename, Err: err})
			continue
		}
		defer f.Close()

		// Parse profile file
		re.opts.Logger.Debugf("Loading profile %s", filename)
		profile, err := LoadProfile(f, filepath.Base(filename))
		if err != nil {
			result = multierror.Append(result, err)
			continue
		}

		if profile.Selector != "" {
			for _, rule := range profile.Rules {
				rule.Expression = profile.Selector + " && " + rule.Expression
			}
		}

		macros, rules, mErr := profile.GetValidMacroAndRules()
		if mErr.ErrorOrNil() != nil {
			result = multierror.Append(result, mErr)
		}

		if len(macros) > 0 {
			// Add the macros to the ruleset and generate macros evaluators
			if err := ruleSet.AddMacros(macros); err != nil {
				result = multierror.Append(result, err)
			}
		}

		// Add rules to the ruleset and generate rules evaluators
		if err := ruleSet.AddRules(rules); err.ErrorOrNil() != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}

func (re *RuleEngine) Load(directory string) *multierror.Error {
	var result *multierror.Error

	if err := LoadPolicies(directory, re.policy); err != nil {
		result = multierror.Append(result, err)
	}

	if err := re.LoadProfiles(directory); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

func (re *RuleEngine) GetPolicy() *RuleSet {
	return re.policy
}

func NewRuleEngine(model eval.Model, eventCtor func() eval.Event, opts *Opts) *RuleEngine {
	return &RuleEngine{
		model:     model,
		eventCtor: eventCtor,
		opts:      opts,
		pool:      eval.NewContextPool(),
		logger:    opts.Logger,
		policy:    NewRuleSet(model, eventCtor, opts),
	}
}
