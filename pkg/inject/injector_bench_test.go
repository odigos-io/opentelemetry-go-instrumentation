package inject

import (
	"encoding/json"
	"testing"
)

func loadOffsets(b *testing.B) *TrackedOffsets {
	b.Helper()
	var offsets TrackedOffsets
	if err := json.Unmarshal([]byte(offsetsData), &offsets); err != nil {
		b.Fatal(err)
	}
	return &offsets
}

func BenchmarkGetFieldOffset_Linear(b *testing.B) {
	inj := &Injector{data: loadOffsets(b)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := inj.getFieldOffset("go", "1.18", "net/http.Request", "Method")
		if !ok {
			b.Fatal("offset not found")
		}
		_, ok = inj.getFieldOffset("google.golang.org/grpc", "v1.44.0", "google.golang.org/grpc.ClientConn", "target")
		if !ok {
			b.Fatal("offset not found")
		}
	}
}

func BenchmarkUnmarshalOffsets(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var offsets TrackedOffsets
		if err := json.Unmarshal([]byte(offsetsData), &offsets); err != nil {
			b.Fatal(err)
		}
	}
}
