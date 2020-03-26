package bridge

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// RoleRepresentation struct
type RoleRepresentation struct {
	ClientRole  *bool   `json:"clientRole,omitempty"`
	Composite   *bool   `json:"composite,omitempty"`
	ContainerID *string `json:"containerId,omitempty"`
	Description *string `json:"description,omitempty"`
	ID          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
}
