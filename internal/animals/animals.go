// Package animals provides a list of animal names used as sanitized
// replacements for real names in JSON data. This keeps sanitized output
// readable (you can still tell values apart) without leaking real data.
package animals

import (
	"math/rand"
	"os"
	"strconv"
	"time"
)

// animals is the pool of names we draw replacements from.
// ~60 entries gives enough variety that repeated names aren't obvious.
var animalNames = []string{
	"Aardvark", "Albatross", "Alpaca", "Axolotl",
	"Badger", "Binturong", "Bison", "Capybara",
	"Cassowary", "Chameleon", "Chinchilla", "Cockatoo",
	"Dingo", "Echidna", "Flamingo", "Galago",
	"Giraffe", "Hedgehog", "Ibis", "Iguana",
	"Jabiru", "Jaguar", "Kakapo", "Kangaroo",
	"Kinkajou", "Lemur", "Liger", "Manatee",
	"Meerkat", "Narwhal", "Numbat", "Ocelot",
	"Okapi", "Olm", "Pangolin", "Platypus",
	"Porcupine", "Quokka", "Quoll", "Raccoon",
	"Salamander", "Serval", "Sloth", "Tapir",
	"Tarsier", "Tenrec", "Uakari", "Vicuna",
	"Walrus", "Wombat", "Wolverine", "Xenops",
	"Yak", "Zebrafish", "Zorilla", "Agouti",
	"Babirusa", "Caiman", "Dugong", "Eland",
}

// rng is our random number generator, seeded once when the program starts.
// We use math/rand (not crypto/rand) because we want speed, not security —
// these are fake names, not cryptographic keys.
var rng *rand.Rand

// init runs automatically when the package is first imported.
// It seeds the random source so each run produces different animal names.
// Set SANITIZER_SEED to an integer for deterministic output (useful in tests).
func init() {
	seed := time.Now().UnixNano() // default: different every run

	// Allow a fixed seed for testing — SANITIZER_SEED=42 always gives same names
	if s := os.Getenv("SANITIZER_SEED"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			seed = n
		}
	}

	// rand.New with a Source is the modern way to get a non-global RNG in Go.
	// Using the global rand functions works too but shares state across goroutines.
	rng = rand.New(rand.NewSource(seed))
}

// Random returns one animal name chosen at random from the list.
// Each call independently picks a name — the same original value may
// become different animals in different fields, which is intentional
// (the goal is sanitization, not consistent pseudonymization).
func Random() string {
	return animalNames[rng.Intn(len(animalNames))]
}
