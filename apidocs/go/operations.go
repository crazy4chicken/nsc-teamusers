package apidocs

// All explicitly aggregates operation metadata in the order supplied.
func All(groups ...[]Operation) []Operation {
	var total int
	for _, group := range groups {
		total += len(group)
	}
	all := make([]Operation, 0, total)
	for _, group := range groups {
		all = append(all, group...)
	}
	return all
}
