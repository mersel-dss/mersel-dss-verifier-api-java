#!/bin/bash

# XAdES Detached İmza Doğrulama Örneği

API_URL="${API_URL:-http://localhost:8086}"
SIGNATURE_XML="${1:-signature.xml}"
ORIGINAL_DOC="${2:-original-document.xml}"
LEVEL="${3:-COMPREHENSIVE}"

if [ ! -f "$SIGNATURE_XML" ]; then
    echo "Hata: İmza dosyası bulunamadı: $SIGNATURE_XML"
    echo "Kullanım: $0 <signature-xml-file> <original-document-file> [level]"
    echo "Level: SIMPLE | COMPREHENSIVE (default: COMPREHENSIVE)"
    exit 1
fi

if [ ! -f "$ORIGINAL_DOC" ]; then
    echo "Hata: Orijinal doküman bulunamadı: $ORIGINAL_DOC"
    echo "Kullanım: $0 <signature-xml-file> <original-document-file> [level]"
    exit 1
fi

echo "XAdES detached imza doğrulama yapılıyor..."
echo "İmza dosyası: $SIGNATURE_XML"
echo "Orijinal doküman: $ORIGINAL_DOC"
echo "Seviye: $LEVEL"
echo ""

curl -X POST "$API_URL/api/v1/verify/xades" \
  -H "Accept: application/json" \
  -F "signedDocument=@$SIGNATURE_XML" \
  -F "originalDocument=@$ORIGINAL_DOC" \
  -F "level=$LEVEL" \
  | jq '.'

echo ""
echo "İşlem tamamlandı."

