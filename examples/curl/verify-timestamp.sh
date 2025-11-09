#!/bin/bash

# Zaman Damgası Doğrulama Örneği

API_URL="${API_URL:-http://localhost:8086}"
TIMESTAMP_FILE="${1:-timestamp.tst}"
ORIGINAL_DATA="${2:-}"

if [ ! -f "$TIMESTAMP_FILE" ]; then
    echo "Hata: Zaman damgası dosyası bulunamadı: $TIMESTAMP_FILE"
    echo "Kullanım: $0 <timestamp-file> [original-data-file]"
    exit 1
fi

echo "Zaman damgası doğrulaması yapılıyor..."
echo "Timestamp dosyası: $TIMESTAMP_FILE"

if [ -n "$ORIGINAL_DATA" ] && [ -f "$ORIGINAL_DATA" ]; then
    echo "Orijinal veri: $ORIGINAL_DATA"
    echo ""
    
    curl -X POST "$API_URL/api/v1/verify/timestamp" \
      -H "Accept: application/json" \
      -F "timestampToken=@$TIMESTAMP_FILE" \
      -F "originalData=@$ORIGINAL_DATA" \
      -F "validateCertificate=true" \
      | jq '.'
else
    echo ""
    
    curl -X POST "$API_URL/api/v1/verify/timestamp" \
      -H "Accept: application/json" \
      -F "timestampToken=@$TIMESTAMP_FILE" \
      -F "validateCertificate=true" \
      | jq '.'
fi

echo ""
echo "İşlem tamamlandı."

