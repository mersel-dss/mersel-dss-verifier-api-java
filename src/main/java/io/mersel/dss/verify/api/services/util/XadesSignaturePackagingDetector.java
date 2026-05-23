package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import io.mersel.dss.verify.api.models.enums.SignaturePackaging;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * XAdES imzasının paketleme tipini ({@link SignaturePackaging#ENVELOPED} /
 * {@link SignaturePackaging#ENVELOPING} / {@link SignaturePackaging#DETACHED})
 * W3C XMLDSig kurallarına göre tip-bazlı (sıra-bağımsız) olarak tespit eder.
 *
 * <h3>Neden ayrı bir tespit ediciye ihtiyacımız var?</h3>
 * <p>DSS 6.3, {@code SignatureWrapper} veya {@code AdvancedSignature} arayüzü
 * üzerinden paketleme tipini doğrulama tarafında raporlamıyor. DSS'in
 * {@link eu.europa.esig.dss.enumerations.SignaturePackaging} enum'u yalnızca
 * imza <b>üretirken</b> parametre olarak alınıyor; verification akışında bu
 * bilgi kayboluyor. Operatöre — özellikle e-Fatura/e-Arşiv ekosistemindeki
 * Türk muhasebe uygulamalarına — TÜBİTAK İMZAGER UI'siyle aynı semantikteki
 * "İmza Türü" alanını üretmek için hesabı kendimiz yapıyoruz.</p>
 *
 * <h3>Algoritma (sıra-bağımsız, rol-bazlı)</h3>
 * <ol>
 *   <li>{@code ds:Signature}'ın <b>direct child</b> {@code ds:SignedInfo}'sunu
 *       bul.</li>
 *   <li>{@code SignedInfo}'nun <b>direct child</b> {@code ds:Reference}
 *       elemanlarını topla (timestamp veya UnsignedProperties altındaki
 *       nested Reference'lar hariç).</li>
 *   <li>Her Reference'ın <b>{@code Type}</b> attribute'una göre rolünü ayırır:
 *       {@code …#SignedProperties} ve {@code …#KeyInfo} / {@code …#X509Data}
 *       gibi meta referansları paketleme kararından <em>dışlar</em>.
 *       SignedProperties URI'sinin KamuSM legacy varyantı
 *       (<code>…/v1.3.2/XAdES.xsd#SignedProperties</code>) de meta sayılır
 *       — yoksa AXA SİGORTA tipi e-Fatura imzaları yanlış sınıflandırılır.</li>
 *   <li>Kalan data referansı/referansları için karar:
 *     <ul>
 *       <li>Bir {@code ds:Transform Algorithm="…#enveloped-signature"} varsa
 *           → {@link SignaturePackaging#ENVELOPED}.</li>
 *       <li>{@code URI=""} (boş) ve enveloped transform yoksa da
 *           {@link SignaturePackaging#ENVELOPED} (W3C XMLDSig'in "entire
 *           enclosing document" konvansiyonu).</li>
 *       <li>{@code URI="#id"} ve {@code #id} <b>aynı</b> {@code ds:Signature}
 *           içinde bir {@code ds:Object} elementini işaret ediyorsa
 *           → {@link SignaturePackaging#ENVELOPING}.</li>
 *       <li>Aksi tüm durumlar (external URI, sibling {@code #id},
 *           {@code file:}/{@code http:}) →
 *           {@link SignaturePackaging#DETACHED}.</li>
 *     </ul>
 *   </li>
 *   <li>Birden çok data referansı varsa öncelik:
 *       {@code ENVELOPED > ENVELOPING > DETACHED} — birleşik kalıplarda
 *       (örn. manifest + enveloped) en kapsayıcı tip raporlanır.</li>
 * </ol>
 *
 * <h3>Neden pozisyonel değil, tip-bazlı?</h3>
 * <p>{@code mersel-dss-server-signer-java} projesinin <code>DSS_OVERRIDE.md</code>'sinde
 * "İMZAGER pozisyonel okur" iddiası yer alıyor ve bu, ilk implementasyonumuzu
 * pozisyonel yapmaya itmişti. Ancak sahada AXA SİGORTA gibi büyük
 * üreticilerin DSS-orijinal sıralı (data önce, SignedProperties sonra)
 * e-Fatura ApplicationResponse imzaları için İMZAGER hâlâ "Tümleşik"
 * (W3C ENVELOPED) raporluyor. Yani İMZAGER pozisyonel <em>değil</em>;
 * meta ref'leri Type attribute'undan filtreliyor. Pozisyonel algoritma bu
 * sınıf imzalarda yanlış pozitif DETACHED üretiyordu — bug fix.</p>
 *
 * <h3>Standart referansları</h3>
 * <ul>
 *   <li><a href="https://www.w3.org/TR/xmldsig-core/#sec-Signature">W3C XMLDSig §4 (Signature element)</a></li>
 *   <li><a href="https://www.w3.org/TR/xmldsig-core/#sec-EnvelopedSignature">W3C XMLDSig §6.6.4 (Enveloped Signature Transform)</a></li>
 *   <li>ETSI EN 319 132-1 §4.2 (XAdES paketleme — W3C semantiğini benimser)</li>
 *   <li>ETSI TS 103 171 (XAdES Baseline Profile — TÜBİTAK BES'in temel referansı)</li>
 * </ul>
 *
 * <h3>Thread-safety</h3>
 * <p>Stateless; tüm metodlar kendi argümanlarıyla çalışır. Spring tarafından
 * singleton olarak yönetilir.</p>
 */
@Component
public class XadesSignaturePackagingDetector {

    private static final Logger logger =
            LoggerFactory.getLogger(XadesSignaturePackagingDetector.class);

    /** W3C XMLDSig namespace ({@code ds:} prefix'inin URI'si). */
    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

    /** Enveloped Signature Transform algoritma URI'si — W3C XMLDSig §6.6.4. */
    private static final String ENVELOPED_TRANSFORM =
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /**
     * SignedProperties referansının {@code Type} attribute değerleri.
     * Üç tarihsel varyantı da kabul ediyoruz çünkü Türkiye ekosisteminde
     * v1.1.1 / v1.2.2 / current sürümlerin hepsi vahşi doğada karşımıza
     * çıkıyor (ayrıca KamuSM-spesifik "{@code XAdES.xsd}" yanlış varyantı
     * için {@link LegacyTurkishXadesTypeUriDetector} ayrı çalışır).
     */
    private static final String[] SIGNED_PROPERTIES_TYPES = {
            "http://uri.etsi.org/01903#SignedProperties",
            "http://uri.etsi.org/01903/v1.1.1#SignedProperties",
            "http://uri.etsi.org/01903/v1.2.2#SignedProperties"
    };

    /**
     * AdvancedSignature için XAdES paketleme tipini hesaplar.
     *
     * @param signature DSS validator'ından gelen imza objesi
     * @return {@link SignaturePackaging#ENVELOPED} / {@link SignaturePackaging#ENVELOPING}
     *         / {@link SignaturePackaging#DETACHED}; XAdES değilse veya DOM
     *         erişilemezse {@code null}
     */
    public SignaturePackaging detect(AdvancedSignature signature) {
        if (!(signature instanceof XAdESSignature)) {
            return null;
        }
        Element sigElement = ((XAdESSignature) signature).getSignatureElement();
        if (sigElement == null) {
            return null;
        }

        try {
            return detectFromSignatureElement(sigElement, safeId(signature));
        } catch (RuntimeException e) {
            // DOM gezintisinde beklenmedik bir şey olursa paketlemeyi
            // raporlamamayı tercih ederiz; doğrulama akışını bozmamalı.
            logger.warn("XAdES packaging detection failed for signatureId={}: {}",
                    safeId(signature), e.getMessage());
            return null;
        }
    }

    /**
     * Tip-bazlı asıl karar mantığı. Unit-test için package-private.
     *
     * @param sigElement {@code ds:Signature} DOM elementi
     * @param signatureId log telemetrisi için (sadece debug mesajlarında kullanılır)
     */
    SignaturePackaging detectFromSignatureElement(Element sigElement, String signatureId) {
        // SignedInfo'nun DIRECT child Reference'larını ekleniş sırasıyla topla.
        // getElementsByTagNameNS kullanmıyoruz çünkü o, UnsignedSignatureProperties
        // veya timestamp içindeki Reference'ları da çekerdi.
        Element signedInfo = directChild(sigElement, "SignedInfo");
        if (signedInfo == null) {
            logger.debug("XAdES packaging: ds:SignedInfo bulunamadı (signatureId={})", signatureId);
            return null;
        }

        List<Element> refs = directChildren(signedInfo, "Reference");
        if (refs.isEmpty()) {
            logger.debug("XAdES packaging: SignedInfo altında Reference yok (signatureId={})", signatureId);
            return null;
        }

        boolean envelopedFound = false;
        boolean envelopingFound = false;
        boolean detachedFound = false;

        for (Element ref : refs) {
            String type = ref.getAttribute("Type");

            // Meta referansları paketleme kararından dışla.
            // (SignedProperties + KeyInfo benzeri X509 type'lar.)
            if (isMetaReferenceType(type)) {
                continue;
            }

            // (a) Enveloped Signature Transform → ENVELOPED.
            if (hasEnvelopedTransform(ref)) {
                envelopedFound = true;
                continue;
            }

            String uri = ref.getAttribute("URI");

            // (c) URI=#id iç ds:Object'i işaret ediyorsa → ENVELOPING.
            if (uri != null && uri.startsWith("#") && pointsToInternalObject(ref, sigElement)) {
                envelopingFound = true;
                continue;
            }

            // (b) URI="" → ENVELOPED (klasik root-sign kalıbı, transform olmadan).
            if (uri == null || uri.isEmpty()) {
                envelopedFound = true;
                continue;
            }

            // (d) External URI veya sibling #id → DETACHED.
            detachedFound = true;
        }

        // Öncelik sırası: ENVELOPED > ENVELOPING > DETACHED
        // (Aynı imzada birden fazla data ref farklı kalıpta olabilir; "en geniş
        // kapsayan" kalıbı seçeriz.)
        if (envelopedFound) return SignaturePackaging.ENVELOPED;
        if (envelopingFound) return SignaturePackaging.ENVELOPING;
        if (detachedFound) return SignaturePackaging.DETACHED;
        return null;
    }

    private boolean hasEnvelopedTransform(Element reference) {
        NodeList transforms = reference.getElementsByTagNameNS(XMLDSIG_NS, "Transform");
        for (int i = 0; i < transforms.getLength(); i++) {
            Element t = (Element) transforms.item(i);
            if (ENVELOPED_TRANSFORM.equals(t.getAttribute("Algorithm"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@code URI="#someId"} işaret edilen Id'nin <b>bu</b> {@code ds:Signature}
     * altındaki bir {@code ds:Object} elementi olup olmadığını kontrol eder.
     * Sibling {@code #id} (örn. internally-detached XML konteyner) bu kontrolü
     * geçemez ve sonuçta DETACHED'a düşer.
     */
    private boolean pointsToInternalObject(Element reference, Element sigElement) {
        String uri = reference.getAttribute("URI");
        if (uri == null || !uri.startsWith("#")) {
            return false;
        }
        String id = uri.substring(1);
        NodeList objects = sigElement.getElementsByTagNameNS(XMLDSIG_NS, "Object");
        for (int i = 0; i < objects.getLength(); i++) {
            Element obj = (Element) objects.item(i);
            // Id veya ID attribute'u (XMLDSig spec: case-sensitive "Id").
            // Bazı eski üreticilerin "ID" yazdığını da gördük; ikisini de kabul edelim.
            if (id.equals(obj.getAttribute("Id")) || id.equals(obj.getAttribute("ID"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * XAdES "meta" referans türleri: SignedProperties ve KeyInfo (X509Data).
     * Bunlar imzalanmış payload değil, XAdES kontrol/metadata referanslarıdır;
     * paketleme kararında dışarıda bırakılır.
     */
    private boolean isMetaReferenceType(String type) {
        if (type == null || type.isEmpty()) {
            return false;
        }
        if (isSignedPropertiesType(type)) {
            return true;
        }
        // KeyInfo referansı genellikle Type="http://www.w3.org/2000/09/xmldsig#X509Data"
        // veya KeyInfo Type'ı taşır. ETSI EN 319 132-1 §A.2.5'e göre baseline'da
        // KeyInfo referansı tercih edilmez ama bazı imzalarda yer alır.
        return "http://www.w3.org/2000/09/xmldsig#X509Data".equals(type)
                || "http://www.w3.org/2000/09/xmldsig#KeyInfo".equals(type)
                || "http://www.w3.org/2000/09/xmldsig#PGPData".equals(type)
                || "http://www.w3.org/2000/09/xmldsig#SPKIData".equals(type)
                || "http://www.w3.org/2000/09/xmldsig#MgmtData".equals(type);
    }

    private boolean isSignedPropertiesType(String type) {
        if (type == null || type.isEmpty()) return false;
        for (String t : SIGNED_PROPERTIES_TYPES) {
            if (t.equals(type)) return true;
        }
        // KamuSM legacy varyantı (LegacyTurkishXadesTypeUriDetector'ın affettiği
        // pattern): "…/v1.3.2/XAdES.xsd#SignedProperties" — paketleme kararı
        // açısından bu da meta sayılmalı. AXA SİGORTA, Logo, Mikro vb. büyük
        // üreticilerin e-Fatura ApplicationResponse'larında karşımıza çıkıyor.
        return type.contains("uri.etsi.org/01903")
                && type.endsWith("#SignedProperties");
    }

    /**
     * {@code parent} altındaki <em>ilk</em> direct child {@code ds:localName}
     * elementini döner; yoksa {@code null}.
     */
    private Element directChild(Element parent, String localName) {
        Node n = parent.getFirstChild();
        while (n != null) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && XMLDSIG_NS.equals(n.getNamespaceURI())
                    && localName.equals(n.getLocalName())) {
                return (Element) n;
            }
            n = n.getNextSibling();
        }
        return null;
    }

    /**
     * {@code parent} altındaki <em>tüm</em> direct child {@code ds:localName}
     * elementlerini ekleniş sırasıyla döner.
     */
    private List<Element> directChildren(Element parent, String localName) {
        List<Element> result = new ArrayList<>();
        Node n = parent.getFirstChild();
        while (n != null) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && XMLDSIG_NS.equals(n.getNamespaceURI())
                    && localName.equals(n.getLocalName())) {
                result.add((Element) n);
            }
            n = n.getNextSibling();
        }
        return result;
    }

    private String safeId(AdvancedSignature signature) {
        try {
            return signature.getId();
        } catch (Exception ignore) {
            return "<unknown>";
        }
    }
}
