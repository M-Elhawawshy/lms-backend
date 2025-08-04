package main

type ErrorMessage struct {
	Message string            `json:"message"`
	Details map[string]string `json:"details"`
}
