package main

import (
	"encoding/json"
	"fmt"
	"github.com/ekomobile/dadata/v2/client"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ekomobile/dadata/v2"
	"github.com/ekomobile/dadata/v2/api/suggest"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type RequestAddressSearch struct {
	Query string `json:"query"`
}

type RequestGeocode struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type Address struct {
	Source       string      `json:"source"`
	Result       string      `json:"result"`
	PostalCode   string      `json:"postal_code"`
	Country      string      `json:"country"`
	Region       string      `json:"region"`
	CityArea     string      `json:"city_area"`
	CityDistrict string      `json:"city_district"`
	Street       string      `json:"street"`
	House        string      `json:"house"`
	GeoLat       string      `json:"geo_lat"`
	GeoLon       string      `json:"geo_lon"`
	QCGeo        interface{} `json:"qc_geo"`
}

type ResponseAddress struct {
	Addresses []*Address `json:"addresses"`
}

func main() {
	_ = godotenv.Load()

	apiKey := os.Getenv("DADATA_API_KEY")
	secretKey := os.Getenv("DADATA_SECRET_KEY")
	if apiKey == "" || secretKey == "" {
		log.Fatal("Не заданы ключи DADATA_API_KEY и DADATA_SECRET_KEY в окружении")
	}

	creds := client.Credentials{
		ApiKeyValue:    apiKey,
		SecretKeyValue: secretKey,
	}

	api := dadata.NewSuggestApi(
		client.WithCredentialProvider(&creds),
	)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/api/address/search", func(w http.ResponseWriter, r *http.Request) {
		var req RequestAddressSearch
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Не удалось выполнить декодирование", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Query) == "" {
			http.Error(w, "Query пустой", http.StatusBadRequest)
			return
		}

		params := suggest.RequestParams{
			Query: req.Query,
		}
		suggestions, err := api.Address(r.Context(), &params)
		if err != nil {
			http.Error(w, "Ошибка API", http.StatusInternalServerError)
			return
		}

		addresses := make([]*Address, 0, len(suggestions))
		for _, s := range suggestions {
			addresses = append(addresses, &Address{
				Source:       req.Query,
				Result:       s.Value,
				PostalCode:   s.Data.PostalCode,
				Country:      s.Data.Country,
				Region:       s.Data.Region,
				CityArea:     s.Data.CityArea,
				CityDistrict: s.Data.CityDistrict,
				Street:       s.Data.Street,
				House:        s.Data.House,
				GeoLat:       s.Data.GeoLat,
				GeoLon:       s.Data.GeoLon,
				QCGeo:        s.Data.QualityCodeGeoRaw,
			})
		}

		response := ResponseAddress{Addresses: addresses}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	r.Post("/api/address/geocode", func(w http.ResponseWriter, r *http.Request) {
		var req RequestGeocode
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Не удалось выполнить декодирование", http.StatusBadRequest)
			return
		}
		if req.Lat == 0 || req.Lng == 0 {
			http.Error(w, "Ошибка в параметрах координат", http.StatusBadRequest)
			return
		}

		params := suggest.GeolocateParams{
			Lat: fmt.Sprintf("%f", req.Lat),
			Lon: fmt.Sprintf("%f", req.Lng),
		}
		suggestions, err := api.GeoLocate(r.Context(), &params)
		if err != nil {
			http.Error(w, "Ошибка API", http.StatusInternalServerError)
			return
		}

		addresses := make([]*Address, 0, len(suggestions))
		for _, s := range suggestions {
			addresses = append(addresses, &Address{
				Result:       s.Value,
				PostalCode:   s.Data.PostalCode,
				Country:      s.Data.Country,
				Region:       s.Data.Region,
				CityArea:     s.Data.CityArea,
				CityDistrict: s.Data.CityDistrict,
				Street:       s.Data.Street,
				House:        s.Data.House,
				GeoLat:       s.Data.GeoLat,
				GeoLon:       s.Data.GeoLon,
				QCGeo:        s.Data.QualityCodeGeoRaw,
			})
		}

		response := ResponseAddress{Addresses: addresses}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	log.Println("Сервер запущен на порту 8080...")
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		return
	}
}
