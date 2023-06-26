package onepassword

type BaseType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	BaseType
	Email       string   `json:"email"`
	Type        string   `json:"type"`
	State       string   `json:"state"`
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type Account struct {
	BaseType
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

type Group struct {
	BaseType
	Description string   `json:"description,omitempty"`
	State       string   `json:"state"`
	CreatedAt   string   `json:"created_at"`
	Permissions []string `json:"permissions,omitempty"`
}

type Vault struct {
	BaseType
	ContentVersion int `json:"content_version"`
}
