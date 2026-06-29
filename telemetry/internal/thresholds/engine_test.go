package thresholds_test

import (
	"testing"
	"time"

	"github.com/pmx-cloud/agents/telemetry/internal/collectors"
	"github.com/pmx-cloud/agents/telemetry/internal/thresholds"
)

func TestEngine_SetFromJSON_Valid(t *testing.T) {
	e := thresholds.NewEngine()
	data := []byte(`[{"id":"t1","metric":"host_load1","op":">","value":4,"for_seconds":0,"severity":"warn"}]`)
	if err := e.SetFromJSON(data); err != nil {
		t.Fatalf("SetFromJSON: %v", err)
	}
}

func TestEngine_SetFromJSON_Invalid(t *testing.T) {
	e := thresholds.NewEngine()
	if err := e.SetFromJSON([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestEngine_MissingID_Rejected(t *testing.T) {
	e := thresholds.NewEngine()
	err := e.Set([]thresholds.Threshold{{
		Metric: "m", Op: thresholds.OpGT, Value: 1,
		ForSeconds: 0, Severity: thresholds.SeverityWarn,
	}})
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestEngine_MissingMetric_Rejected(t *testing.T) {
	e := thresholds.NewEngine()
	err := e.Set([]thresholds.Threshold{{
		ID: "t1", Op: thresholds.OpGT, Value: 1,
		ForSeconds: 0, Severity: thresholds.SeverityWarn,
	}})
	if err == nil {
		t.Fatal("expected error for empty metric")
	}
}

func TestEngine_LTE_GTE_Operators(t *testing.T) {
	for _, tc := range []struct {
		op    thresholds.Op
		val   float64
		thr   float64
		holds bool
	}{
		{thresholds.OpLTE, 1.0, 1.0, true},
		{thresholds.OpLTE, 1.1, 1.0, false},
		{thresholds.OpGTE, 1.0, 1.0, true},
		{thresholds.OpGTE, 0.9, 1.0, false},
		{thresholds.OpRateBelow, 3.0, 5.0, true},
		{thresholds.OpRateAbove, 6.0, 5.0, true},
	} {
		e := thresholds.NewEngine()
		e.Set([]thresholds.Threshold{{
			ID: "t", Metric: "m", Op: tc.op, Value: tc.thr,
			ForSeconds: 0, Severity: thresholds.SeverityWarn,
		}})
		e.Evaluate([]collectors.Metric{{Name: "m", Value: tc.val, Timestamp: time.Now()}})
		select {
		case a := <-e.AlertCh:
			if !tc.holds {
				t.Errorf("op=%s val=%v thr=%v: unexpected alert %+v", tc.op, tc.val, tc.thr, a)
			}
		default:
			if tc.holds {
				t.Errorf("op=%s val=%v thr=%v: expected alert, got none", tc.op, tc.val, tc.thr)
			}
		}
	}
}

func TestEngine_ForSeconds_HoldRequired(t *testing.T) {
	e := thresholds.NewEngine()
	e.Set([]thresholds.Threshold{{
		ID: "t", Metric: "m", Op: thresholds.OpGT, Value: 1,
		ForSeconds: 100, // 100 seconds hold required
		Severity:   thresholds.SeverityWarn,
	}})

	// First eval: condition holds but for_seconds not elapsed.
	e.Evaluate([]collectors.Metric{{Name: "m", Value: 10, Timestamp: time.Now()}})
	select {
	case a := <-e.AlertCh:
		t.Fatalf("should not fire before for_seconds elapsed: %+v", a)
	default:
		// Good.
	}
}

func TestEngine_Evaluate_UnknownMetricIgnored(t *testing.T) {
	e := thresholds.NewEngine()
	e.Set([]thresholds.Threshold{{
		ID: "t", Metric: "nonexistent_metric", Op: thresholds.OpGT, Value: 1,
		ForSeconds: 0, Severity: thresholds.SeverityWarn,
	}})
	// Batch doesn't contain the metric — must not panic.
	e.Evaluate([]collectors.Metric{{Name: "other_metric", Value: 999, Timestamp: time.Now()}})
}

func TestEngine_EmptySet_NoOp(t *testing.T) {
	e := thresholds.NewEngine()
	e.Set([]thresholds.Threshold{})
	e.Evaluate([]collectors.Metric{{Name: "m", Value: 999, Timestamp: time.Now()}})
}
