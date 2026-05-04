package ingest

import "strings"

const (
	DefaultChunkSize    = 512
	DefaultChunkOverlap = 64
)

// ChunkText splits text into overlapping chunks of up to size characters.
// It tries to break on paragraph and sentence boundaries before falling back
// to hard character splits, so each chunk remains semantically coherent.
func ChunkText(text string, size, overlap int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) <= size {
		return []string{text}
	}

	// Split into natural segments: paragraphs first, then sentences.
	segments := splitSegments(text)

	var chunks []string
	var current strings.Builder

	flush := func() {
		s := strings.TrimSpace(current.String())
		if s != "" {
			chunks = append(chunks, s)
		}
		// carry overlap from end of this chunk into the next
		if overlap > 0 && len(s) > overlap {
			current.Reset()
			current.WriteString(s[len(s)-overlap:])
			current.WriteByte(' ')
		} else {
			current.Reset()
		}
	}

	for _, seg := range segments {
		// If adding this segment would exceed the limit, flush first.
		if current.Len()+len(seg) > size && current.Len() > 0 {
			flush()
		}
		// If a single segment is larger than size, hard-split it.
		for len(seg) > size {
			remaining := size - current.Len()
			if remaining <= 0 {
				flush()
				remaining = size
			}
			current.WriteString(seg[:remaining])
			seg = seg[remaining:]
			flush()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(seg)
	}
	flush()
	return chunks
}

// splitSegments breaks text into paragraph → sentence granularity.
func splitSegments(text string) []string {
	var out []string
	for _, para := range strings.Split(text, "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		// split paragraph into sentences
		for _, sent := range splitSentences(para) {
			if s := strings.TrimSpace(sent); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// splitSentences splits on ". ", "! ", "? " boundaries.
func splitSentences(text string) []string {
	var sentences []string
	start := 0
	for i := 0; i < len(text)-1; i++ {
		if (text[i] == '.' || text[i] == '!' || text[i] == '?') && text[i+1] == ' ' {
			sentences = append(sentences, text[start:i+1])
			start = i + 2
		}
	}
	if start < len(text) {
		sentences = append(sentences, text[start:])
	}
	return sentences
}
