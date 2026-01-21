package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
)

var adjectives = []string{
	"agile", "ancient", "angry", "bashful", "blissful", "breezy", "brisk",
	"bubbly", "careful", "charming", "cheerful", "clever", "clumsy", "cosmic",
	"cozy", "cunning", "curious", "daring", "drowsy", "eager", "epic",
	"fancy", "feisty", "fluffy", "fuzzy", "gentle", "giddy", "gloomy",
	"glorious", "graceful", "grumpy", "happy", "helpful", "hungry", "jolly",
	"juicy", "lazy", "lively", "lucky", "mighty", "mysterious", "nervous",
	"nimble", "noisy", "odd", "patient", "playful", "polite", "proud",
	"quirky", "rapid", "restless", "shiny", "silent", "silly", "sleepy",
	"sly", "smiling", "snarky", "sparkly", "spicy", "spry", "stealthy",
	"stubborn", "swift", "tiny", "tranquil", "vivid", "wary", "wild",
	"witty", "zany", "zesty",
}

var nouns = []string{
	"alpaca", "antelope", "badger", "bat", "beaver", "bison", "buffalo",
	"camel", "capybara", "cat", "chameleon", "cheetah", "cobra", "corgi",
	"cougar", "coyote", "crab", "crow", "deer", "dingo", "dolphin",
	"donkey", "dragon", "eagle", "eel", "elephant", "falcon", "ferret",
	"fox", "frog", "gecko", "giraffe", "goat", "goose", "gorilla",
	"hamster", "hedgehog", "heron", "hippo", "hyena", "ibis", "jaguar",
	"jellyfish", "kangaroo", "kiwi", "koala", "lemur", "leopard", "lion",
	"llama", "lobster", "lynx", "mammoth", "manatee", "marmot", "meerkat",
	"mole", "monkey", "moose", "narwhal", "octopus", "opossum", "orca",
	"otter", "owl", "ox", "panda", "panther", "parrot", "peacock",
	"pelican", "penguin", "pig", "pigeon", "puma", "quail", "rabbit",
	"raccoon", "ram", "raven", "rhino", "robin", "salamander", "seal",
	"shark", "sheep", "sloth", "snail", "snake", "sparrow", "squid",
	"squirrel", "stallion", "stork", "swan", "tiger", "toad", "turkey",
	"turtle", "urchin", "viper", "vulture", "walrus", "weasel", "whale",
	"wolf", "wombat", "yak", "zebra",
}

// Optional blacklist if you ever want to filter specific combos.
var blacklist = map[string]bool{
	"boring-wozniak": true, // classic Docker easter egg.
}

// Random returns a random "adjective_noun" pair, e.g. "sparkly_lemur".
func Random() string {
	for {
		a := adjectives[rand.Intn(len(adjectives))]
		n := nouns[rand.Intn(len(nouns))]
		name := fmt.Sprintf("%s_%s", a, n)
		if !blacklist[name] {
			return name
		}
	}
}

// Deterministic returns a stable "adjective_noun" pair derived from id.
// Same id -> same name, using SHA-256 for indexing.
func Deterministic(id string) string {
	h := sha256.Sum256([]byte(id))

	aIdx := binary.BigEndian.Uint32(h[0:4]) % uint32(len(adjectives))
	nIdx := binary.BigEndian.Uint32(h[4:8]) % uint32(len(nouns))

	name := fmt.Sprintf("%s_%s", adjectives[aIdx], nouns[nIdx])

	// If blacklisted, bump indices deterministically.
	if blacklist[name] {
		aIdx = (aIdx + 1) % uint32(len(adjectives))
		nIdx = (nIdx + 1) % uint32(len(nouns))
		name = fmt.Sprintf("%s_%s", adjectives[aIdx], nouns[nIdx])
	}

	return name
}

// GenerateFunnyName chooses mode:
//   - no args      -> Random()
//   - one string   -> Deterministic(id)
func GenerateFunnyName(id string) string {
	if len(id) == 0 {
		return Random()
	}
	return Deterministic(id)
}
