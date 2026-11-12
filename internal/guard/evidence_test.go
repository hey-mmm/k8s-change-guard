package guard

import (
	"math"
	"strings"
	"testing"
)

func TestEvidenceTimestampFromUsesLatestPositiveRawTimestamp(t *testing.T) {
	points := []evdPoint{
		{timestamp: 10, value: 10},
		{timestamp: 20, value: 0},
		{timestamp: 30, value: -5},
		{timestamp: 40, value: 75},
	}
	timestamp, ok := evdTimestampFrom(points)
	if !ok || timestamp != 75 {
		t.Fatalf("expected latest positive source timestamp 75, got %v (%v)", timestamp, ok)
	}
	if _, ok := evdTimestampFrom(nil); ok {
		t.Fatal("empty samples must not produce a timestamp")
	}
	if _, ok := evdTimestampFrom([]evdPoint{{timestamp: 1, value: 0}}); ok {
		t.Fatal("zero source timestamp must not be accepted")
	}
}

func TestEvidenceMaxPointByTimestampUsesFreshnessNotMagnitude(t *testing.T) {
	points := []evdPoint{
		{timestamp: 100, value: 900},
		{timestamp: 200, value: 3},
		{timestamp: 150, value: 700},
	}
	point, ok := evdMaxPointByTimestamp(points)
	if !ok || point.timestamp != 200 || point.value != 3 {
		t.Fatalf("expected newest point, got %+v", point)
	}
}

func TestEvidencePromResultValuesUsesLatestMatrixSample(t *testing.T) {
	payload := M{"data": M{
		"resultType": "matrix",
		"result": []any{
			M{"values": []any{
				[]any{float64(10), "1"},
				[]any{float64(20), "2"},
			}},
			M{"values": []any{
				[]any{float64(30), "3"},
				[]any{float64(40), "4"},
			}},
		},
	}}
	values, resultType := evdPromResultValues(payload)
	if resultType != "matrix" || len(values) != 2 {
		t.Fatalf("unexpected result: %v %v", resultType, values)
	}
	if values[0].timestamp != 20 || values[1].timestamp != 40 {
		t.Fatalf("expected latest sample per series, got %+v", values)
	}
}

func TestEvidenceQuantityParsing(t *testing.T) {
	cases := map[string]float64{
		"512Mi": 512 * 1024 * 1024,
		"1Gi":   1024 * 1024 * 1024,
		"250m":  0.25,
		"1.5":   1.5,
		"2Ki":   2048,
	}
	for input, expected := range cases {
		value, ok := evdQuantity(input)
		if !ok || math.Abs(value-expected) > 1e-9 {
			t.Fatalf("evdQuantity(%q) = %v (%v), want %v", input, value, ok, expected)
		}
	}
	for _, invalid := range []any{true, nil, "1Xi", "not-a-quantity", math.NaN()} {
		if _, ok := evdQuantity(invalid); ok {
			t.Fatalf("evdQuantity accepted invalid value %v", invalid)
		}
	}
}

func TestEvidenceBoundedRawTruncatesSeries(t *testing.T) {
	series := make([]any, 0, 25)
	for index := 0; index < 25; index++ {
		series = append(series, M{"metric": M{"index": index}, "value": []any{float64(index), "1"}})
	}
	result := evdBoundedRaw(M{"status": "success", "data": M{"resultType": "vector", "result": series}})
	if Bool(result["_truncated"]) != true {
		t.Fatal("expected truncation marker")
	}
	data := Obj(result["data"])
	if len(Arr(data["result"])) != 20 {
		t.Fatalf("expected raw result bounded to 20 series, got %d", len(Arr(data["result"])))
	}
}

func TestCollectFailsClosedWithoutValidConfig(t *testing.T) {
	result := Collect(nil)
	if len(Arr(result["errors"])) == 0 {
		t.Fatal("nil evidence config did not fail closed")
	}
	if !strings.Contains(Str(Arr(result["errors"])[0]), "mapping") {
		t.Fatalf("unexpected error: %v", result["errors"])
	}
	if _, ok := result["metrics"].(M); !ok {
		t.Fatal("error result is missing bounded metrics")
	}
}
