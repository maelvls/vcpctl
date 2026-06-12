package main

import "github.com/maelvls/vcpctl/api"

// buildServiceAccountNameCounts returns a map of service account names to their
// occurrence count. Used to detect duplicate names when rendering manifests.
func buildServiceAccountNameCounts(allSAs []api.ServiceAccountDetails) map[string]int {
	nameCounts := make(map[string]int)
	for _, sa := range allSAs {
		nameCounts[sa.Name]++
	}
	return nameCounts
}

// isDuplicateName returns true if the given name appears multiple times.
func isDuplicateName(name string, nameCounts map[string]int) bool {
	return nameCounts[name] > 1
}
