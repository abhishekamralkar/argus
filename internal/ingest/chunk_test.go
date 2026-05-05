package ingest

import "testing"

func TestChunkText(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		size        int
		overlap     int
		wantNil     bool
		wantSingle  bool
		wantContent string // only checked when wantSingle is true
		wantMulti   bool
	}{
		{
			name:    "empty string returns nil",
			text:    "",
			size:    512,
			overlap: 64,
			wantNil: true,
		},
		{
			name:    "whitespace-only string returns nil",
			text:    "   ",
			size:    512,
			overlap: 64,
			wantNil: true,
		},
		{
			name:        "text shorter than size returns single chunk equal to trimmed input",
			text:        "hello world",
			size:        512,
			overlap:     0,
			wantSingle:  true,
			wantContent: "hello world",
		},
		{
			name:      "text longer than size produces multiple chunks",
			text:      "This is sentence one. This is sentence two. This is sentence three. This is sentence four. This is sentence five.",
			size:      40,
			overlap:   0,
			wantMulti: true,
		},
		{
			name:    "non-zero overlap produces valid chunks with no panic",
			text:    "Alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega.",
			size:    30,
			overlap: 10,
			// validates no panic and all chunks <= size
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChunkText(tt.text, tt.size, tt.overlap)

			if tt.wantNil {
				if len(got) != 0 {
					t.Errorf("ChunkText(%q, %d, %d) = %v, want nil/empty", tt.text, tt.size, tt.overlap, got)
				}
				return
			}

			if tt.wantSingle {
				if len(got) != 1 {
					t.Errorf("ChunkText(%q, %d, %d) returned %d chunks, want 1", tt.text, tt.size, tt.overlap, len(got))
					return
				}
				if got[0] != tt.wantContent {
					t.Errorf("ChunkText chunk[0] = %q, want %q", got[0], tt.wantContent)
				}
				return
			}

			if tt.wantMulti && len(got) <= 1 {
				t.Errorf("ChunkText(%q, %d, %d) returned %d chunk(s), want more than 1", tt.text, tt.size, tt.overlap, len(got))
			}

			// Every chunk must be within the size limit.
			for i, chunk := range got {
				if len(chunk) > tt.size {
					t.Errorf("chunk[%d] length %d exceeds size %d: %q", i, len(chunk), tt.size, chunk)
				}
			}
		})
	}
}
