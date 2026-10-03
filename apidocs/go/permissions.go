package apidocs

// PermissionDeriver maps a method and path to any- and team-scoped permission keys.
type PermissionDeriver func(method, path string) (anyKey, teamKey string)
