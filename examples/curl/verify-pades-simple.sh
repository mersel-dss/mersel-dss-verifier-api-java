#!/bin/bash

# PAdES (PDF) Basit İmza Doğrulama Örneği

API_URL="${API_URL:-http://localhost:8086}"
SIGNED_PDF="${1:-signed-document.pdf}"

if [ ! -f "$SIGNED_PDF" ]; then
    echo "Hata: İmzalı PDF dosyası bulunamadı: $SIGNED_PDF"
    echo "Kullanım: $0 <signed-pdf-file>"
    exit 1
fi

echo "PAdES basit doğrulama yapılıyor..."
echo "Dosya: $SIGNED_PDF"
echo ""

curl -X POST "$API_URL/api/v1/verify/pades" \
  -H "Accept: application/json" \
  -F "signedDocument=@$SIGNED_PDF" \
  -F "level=SIMPLE" \
  | jq '.'

echo ""
echo "İşlem tamamlandı."

