package tunnel

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type dnsCache struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      list.List
	inflight singleflight.Group
}

type dnsEntry struct {
	key      string
	data     []byte
	inserted time.Time
	lifetime uint32
	ttls     []dnsTTL
}

type dnsTTL struct {
	offset int
	value  uint32
}

const dnsCacheEntries = 256

func (c *dnsCache) get(key string, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.entries[key]
	if element == nil {
		return nil
	}
	entry := element.Value.(*dnsEntry)
	age := uint32(now.Sub(entry.inserted) / time.Second)
	if age >= entry.lifetime {
		c.lru.Remove(element)
		delete(c.entries, key)
		return nil
	}
	c.lru.MoveToFront(element)
	result := bytes.Clone(entry.data)
	for _, ttl := range entry.ttls {
		binary.BigEndian.PutUint32(result[ttl.offset:], ttl.value-age)
	}
	return result
}

func (c *dnsCache) put(entry *dnsEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	if element := c.entries[entry.key]; element != nil {
		c.lru.Remove(element)
	}
	c.entries[entry.key] = c.lru.PushFront(entry)
	if c.lru.Len() > dnsCacheEntries {
		delete(c.entries, c.lru.Remove(c.lru.Back()).(*dnsEntry).key)
	}
}

func (c *dnsCache) resolve(ctx context.Context, direct bool, query []byte, load func([]byte) ([]byte, error)) ([]byte, string, error) {
	end := cacheableQuestion(query)
	if end == 0 {
		data, err := load(query)
		return data, "", err
	}
	// Each engine owns one resolver and filter configuration. Partition the cache
	// further by actual upstream route and all request bits, except the ID.
	wire := bytes.Clone(query)
	keyBytes := bytes.Clone(wire[1:])
	keyBytes[0] = 0
	if direct {
		keyBytes[0] = 1
	}
	key := string(keyBytes)
	withID := func(data []byte) []byte {
		copy(data[:2], query[:2])
		return data
	}
	if data := c.get(key, time.Now()); data != nil {
		return withID(data), "DNS_CACHE_HIT", nil
	}
	result := c.inflight.DoChan(key, func() (any, error) {
		if data := c.get(key, time.Now()); data != nil {
			return data, nil
		}
		data, err := load(wire)
		if err == nil {
			if entry := cacheableAnswer(key, wire, end, data); entry != nil {
				c.put(entry)
			}
		}
		return data, err
	})
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case res := <-result:
		event := "DNS_CACHE_MISS"
		if res.Shared {
			event = "DNS_REQUEST_COALESCED"
		}
		if res.Err != nil {
			return nil, event, res.Err
		}
		return withID(bytes.Clone(res.Val.([]byte))), event, nil
	}
}

func cacheableQuestion(wire []byte) int {
	_, end := dnsQuestion(wire)
	if end == 0 || wire[2]&0xfe != 0 || wire[3]&^byte(0x30) != 0 ||
		binary.BigEndian.Uint32(wire[6:10]) != 0 || binary.BigEndian.Uint16(wire[end-2:]) != 1 {
		return 0
	}
	switch binary.BigEndian.Uint16(wire[end-4:]) {
	case 1, 5, 28: // A, CNAME, AAAA.
	default:
		return 0
	}
	ar := binary.BigEndian.Uint16(wire[10:12])
	if ar == 0 && end == len(wire) {
		return end
	}
	// Permit an empty EDNS(0) OPT, keeping the UDP size and DO bit in the key.
	// Cookies, ECS and any other options are deliberately sent independently.
	if ar == 1 && len(wire) == end+11 && wire[end] == 0 &&
		binary.BigEndian.Uint16(wire[end+1:]) == 41 &&
		binary.BigEndian.Uint32(wire[end+5:])&^0x8000 == 0 &&
		binary.BigEndian.Uint16(wire[end+9:]) == 0 {
		return end
	}
	return 0
}

func cacheableAnswer(key string, query []byte, questionEnd int, data []byte) *dnsEntry {
	if len(data) < questionEnd || len(data) > 8192 || data[2]&0xfa != 0x80 ||
		binary.BigEndian.Uint16(data[4:6]) != 1 || !bytes.Equal(query[12:questionEnd], data[12:questionEnd]) {
		return nil
	}
	rcode := data[3] & 15
	if rcode != 0 && rcode != 3 {
		return nil
	}
	counts := [3]uint16{binary.BigEndian.Uint16(data[6:]), binary.BigEndian.Uint16(data[8:]), binary.BigEndian.Uint16(data[10:])}
	qtype := binary.BigEndian.Uint16(query[questionEnd-4:])
	entry := &dnsEntry{key: key, inserted: time.Now(), lifetime: 3600}
	offset := questionEnd
	hasAnswer, hasSOA := false, false
	for section, count := range counts {
		for range count {
			start := offset
			offset = dnsNameEnd(data, offset)
			if offset < 0 || offset+10 > len(data) {
				return nil
			}
			typ := binary.BigEndian.Uint16(data[offset:])
			class := binary.BigEndian.Uint16(data[offset+2:])
			value := binary.BigEndian.Uint32(data[offset+4:])
			size := int(binary.BigEndian.Uint16(data[offset+8:]))
			rdata, next := offset+10, offset+10+size
			if next > len(data) {
				return nil
			}
			switch {
			case typ == 41: // OPT does not carry a TTL.
				if section != 2 || data[start] != 0 || value&^0x8000 != 0 || size != 0 {
					return nil
				}
			case typ == 249 || typ == 250: // TKEY and TSIG must never be replayed.
				return nil
			default:
				if class != 1 {
					return nil
				}
				if section == 0 && typ == qtype {
					hasAnswer = true
				}
				if section == 1 && typ == 6 {
					mnameEnd := dnsNameEnd(data, rdata)
					if mnameEnd < 0 || mnameEnd >= next || dnsNameEnd(data, mnameEnd) != next-20 {
						return nil
					}
					// Negative lifetime is min(SOA TTL, SOA.MINIMUM), RFC 2308.
					if rcode == 3 || !hasAnswer {
						value = min(value, binary.BigEndian.Uint32(data[next-4:]))
					}
					hasSOA = true
				}
				entry.lifetime = min(entry.lifetime, value)
				entry.ttls = append(entry.ttls, dnsTTL{offset + 4, value})
			}
			offset = next
		}
	}
	if offset != len(data) || entry.lifetime == 0 || ((rcode == 3 || !hasAnswer) && !hasSOA) {
		return nil
	}
	entry.data = bytes.Clone(data)
	return entry
}

// dnsNameEnd walks the wire encoding without expanding names. Pointers must
// point backwards into the message. No offsets are moved when aging TTLs.
func dnsNameEnd(data []byte, offset int) int {
	begin := offset
	for offset < len(data) && offset-begin < 255 {
		n := int(data[offset])
		switch {
		case n == 0:
			return offset + 1
		case n < 64:
			offset += n + 1
		case n >= 192 && offset+1 < len(data):
			pointer := (n&63)<<8 | int(data[offset+1])
			if pointer >= 12 && pointer < offset {
				return offset + 2
			}
			return -1
		default:
			return -1
		}
	}
	return -1
}
