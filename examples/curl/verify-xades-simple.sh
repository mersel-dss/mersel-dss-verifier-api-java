#!/bin/bash

# XAdES (XML) Basit İmza Doğrulama Örneği

API_URL="${API_URL:-http://localhost:8086}"
SIGNED_XML="${1:-signed-document.xml}"

if [ ! -f "$SIGNED_XML" ]; then
    echo "Hata: İmzalı XML dosyası bulunamadı: $SIGNED_XML"
    echo "Kullanım: $0 <signed-xml-file>"
    exit 1
fi

echo "XAdES basit doğrulama yapılıyor..."
echo "Dosya: $SIGNED_XML"
echo ""
echo "Not: DSS otomatik olarak imza tipini tespit eder (Enveloped/Enveloping)"
echo ""

curl -X POST "$API_URL/api/v1/verify/xades" \
  -H "Accept: application/json" \
  -F "signedDocument=@$SIGNED_XML" \
  -F "level=SIMPLE" \
  | jq '.'

echo ""
echo "İşlem tamamlandı."

