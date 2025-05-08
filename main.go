package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	Username     string
	PasswordHash string
	TOTPSecret   string
}

type Response struct {
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	Username   string `json:"username,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
	QRImage    string `json:"qr_image,omitempty"`
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./database.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateTOTPSecret(username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MFA-Go-App",
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func generateQRCode(url string) (string, error) {
	var png []byte
	png, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(png), nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondWithError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(data.Username) < 3 || len(data.Username) > 20 {
		respondWithError(w, "Username must be 3-20 characters", http.StatusBadRequest)
		return
	}

	if len(data.Password) < 8 {
		respondWithError(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", data.Username).Scan(&count)
	if err != nil {
		respondWithError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		respondWithError(w, "Username already exists", http.StatusBadRequest)
		return
	}

	// Generate TOTP secret
	secret, url, err := generateTOTPSecret(data.Username)
	if err != nil {
		respondWithError(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}

	// Hash password
	hashedPassword, err := hashPassword(data.Password)
	if err != nil {
		respondWithError(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Save user
	_, err = db.Exec(
		"INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
		data.Username, hashedPassword, secret,
	)
	if err != nil {
		respondWithError(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Generate QR code
	qrImage, err := generateQRCode(url)
	if err != nil {
		respondWithError(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusCreated, Response{
		Message:    "Registration successful",
		Username:   data.Username,
		TOTPSecret: secret,
		QRImage:    qrImage,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondWithError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get user from database
	var user User
	err := db.QueryRow(
		"SELECT username, password_hash, totp_secret FROM users WHERE username = ?",
		data.Username,
	).Scan(&user.Username, &user.PasswordHash, &user.TOTPSecret)

	if err != nil {
		respondWithError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	if !checkPassword(data.Password, user.PasswordHash) {
		respondWithError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify TOTP code
	valid := totp.Validate(data.TOTPCode, user.TOTPSecret)
	if !valid {
		respondWithError(w, "Invalid TOTP code", http.StatusUnauthorized)
		return
	}

	respondWithJSON(w, http.StatusOK, Response{
		Message: "Login successful",
	})
}

func qrCodeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var secret string
	err := db.QueryRow(
		"SELECT totp_secret FROM users WHERE username = ?",
		username,
	).Scan(&secret)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MFA-Go-App",
		AccountName: username,
		Secret:      []byte(secret),
	})
	if err != nil {
		http.Error(w, "Failed to generate QR", http.StatusInternalServerError)
		return
	}

	// Generate QR code directly to HTTP response
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func respondWithError(w http.ResponseWriter, message string, code int) {
	respondWithJSON(w, code, Response{Error: message})
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filepath := vars["filepath"]

	file, err := os.Open("static/" + filepath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Set content type based on file extension
	switch {
	case len(filepath) > 4 && filepath[len(filepath)-4:] == ".css":
		w.Header().Set("Content-Type", "text/css")
	case len(filepath) > 3 && filepath[len(filepath)-3:] == ".js":
		w.Header().Set("Content-Type", "application/javascript")
	}

	io.Copy(w, file)
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/qrcode/{username}", qrCodeHandler).Methods("GET")
	r.HandleFunc("/static/{filepath:.*}", staticHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         "0.0.0.0:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(srv.ListenAndServe())
}
