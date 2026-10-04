package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.SignedReferenceInfo;
import io.mersel.dss.verify.api.models.TimestampInfo;
import io.mersel.dss.verify.api.models.VerificationRecommendation;
import io.mersel.dss.verify.api.models.enums.ChainRevocationStatus;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Copies DSS report evidence without inferring relationships from XML nesting or changing validation decisions. */
public final class SignatureEvidenceExtractor {
    private SignatureEvidenceExtractor() { }

    public static void enrich(SignatureInfo info, SignatureWrapper wrapper) {
        info.setCounterSignature(wrapper.isCounterSignature());
        SignatureWrapper parent = wrapper.getParent();
        if (parent != null) info.setParentSignatureId(parent.getId());
        List<SignedReferenceInfo> references = new ArrayList<>();
        List<XmlDigestMatcher> matchers = wrapper.getDigestMatchers();
        if (matchers != null) {
            for (XmlDigestMatcher matcher : matchers) {
                if (matcher == null) continue;
                SignedReferenceInfo reference = new SignedReferenceInfo();
                reference.setId(matcher.getId());
                reference.setUri(matcher.getUri());
                reference.setDocumentName(matcher.getDocumentName());
                if (matcher.getType() != null) reference.setType(matcher.getType().name());
                if (matcher.getDigestMethod() != null) reference.setDigestAlgorithm(matcher.getDigestMethod().getName());
                if (matcher.getDigestValue() != null) {
                    reference.setDigestValue(Base64.getEncoder().encodeToString(matcher.getDigestValue()));
                }
                reference.setDataFound(matcher.isDataFound());
                reference.setDataIntact(matcher.isDataIntact());
                reference.setDuplicated(matcher.isDuplicated());
                references.add(reference);
            }
        }
        info.setSignedReferences(references);
        info.setRecommendations(recommendations(info, wrapper));
    }

    /** Builds the inverse relationship only from the parent IDs reported by DSS. */
    public static void connectCounterSignatures(List<SignatureInfo> signatures) {
        Map<String, SignatureInfo> byId = new LinkedHashMap<>();
        for (SignatureInfo signature : signatures) {
            signature.setCounterSignatureIds(new ArrayList<>());
            byId.put(signature.getSignatureId(), signature);
        }
        for (SignatureInfo signature : signatures) {
            SignatureInfo parent = byId.get(signature.getParentSignatureId());
            if (parent != null && Boolean.TRUE.equals(signature.getCounterSignature())
                    && parent != signature && !parent.getCounterSignatureIds().contains(signature.getSignatureId())) {
                parent.getCounterSignatureIds().add(signature.getSignatureId());
            }
        }
    }

    /** Maps explicit DSS policy warning keys to the legacy preservation guidance. */
    public static void enrichPolicyRecommendations(SignatureInfo info, DetailedReport report) {
        if (report == null || info.getSignatureId() == null) return;
        List<VerificationRecommendation> recommendations = info.getRecommendations();
        if (recommendations == null) {
            recommendations = new ArrayList<>();
            info.setRecommendations(recommendations);
        }
        List<Message> warnings = new ArrayList<>();
        addMessages(warnings, report.getAdESValidationWarnings(info.getSignatureId()));
        if (info.getTimestamps() != null) {
            for (TimestampInfo timestamp : info.getTimestamps()) {
                if (timestamp.getTimestampId() != null) {
                    addMessages(warnings, report.getAdESValidationWarnings(timestamp.getTimestampId()));
                    addMessages(warnings, report.getAdESValidationErrors(timestamp.getTimestampId()));
                }
            }
        }
        if (info.isValid() && hasKey(warnings, "ASCCM_DAA_ANS", "ASCCM_DAA_ANS_2")) {
            recommendations.add(recommendation("ARCHIVE_REQUIRED_DIGEST_POLICY", "Geçersiz özet algoritması: imza en kısa sürede arşivlenmelidir",
                    "DSS, etkin politikanın özet algoritması kısıtını uyarı olarak bildirdi. Doğrulama sonucu korunmuştur; uygun algoritmayla arşiv koruması planlayın.", "WARNING"));
        }
        if (info.isValid() && hasKey(warnings, "BBB_XCV_IRDPFC_ANS", "BBB_XCV_IARDPFC_ANS",
                "BBB_RFC_IRIF_ANS", "BBB_XCV_IRDC_ANS", "ADEST_RORPIIC_ANS",
                "BBB_XCV_ICTIVRCIRI_ANS", "BBB_XCV_IRDPFRC_ANS")) {
            recommendations.add(recommendation("ARCHIVE_REQUIRED_REVOCATION_EVIDENCE", "Dosya arşivlenmelidir",
                    "DSS, sertifika veya zaman damgası iptal kanıtı için sorun bildirdi. Doğrulama sonucu korunmuştur; gerekli OCSP/SİL verilerini tamamlayıp arşiv koruması sağlayın.", "WARNING"));
        }
        if (!info.isValid()) {
            List<Message> errors = report.getAdESValidationErrors(info.getSignatureId());
            if (hasKey(errors, "BBB_XCV_IRDPFC_ANS", "BBB_XCV_IARDPFC_ANS", "BBB_XCV_IRDPFRC_ANS")
                    || "NO_SIGNING_CERTIFICATE_FOUND".equals(info.getSubIndication())
                    || "NO_CERTIFICATE_CHAIN_FOUND".equals(info.getSubIndication())
                    || "SIGNED_DATA_NOT_FOUND".equals(info.getSubIndication())) {
                recommendations.add(recommendation("VALIDATION_EVIDENCE_INCOMPLETE", "Eksik bilginin tamamlanması gerekmektedir",
                        "DSS gerekli sertifika, iptal kanıtı veya imzalı içeriğe ulaşamadı. Eksik veriyi tamamlayıp yeniden doğrulayın; bu öneri sonucu geçerli yapmaz.", "WARNING"));
            }
        }
    }

    private static void addMessages(List<Message> target, List<Message> messages) {
        if (messages != null) target.addAll(messages);
    }

    private static boolean hasKey(List<Message> messages, String... keys) {
        if (messages == null) return false;
        for (Message message : messages) {
            if (message == null) continue;
            for (String key : keys) if (key.equals(message.getKey())) return true;
        }
        return false;
    }

    private static List<VerificationRecommendation> recommendations(SignatureInfo info, SignatureWrapper wrapper) {
        List<VerificationRecommendation> result = new ArrayList<>();
        if (wrapper.getArchiveTimestamps() == null || wrapper.getArchiveTimestamps().isEmpty()) {
            result.add(recommendation("ARCHIVE_TIMESTAMP_MISSING", "Arşiv zaman damgası bulunamadı",
                    "DSS raporunda arşiv zaman damgası yok. Uzun süreli saklama için doğrulama verilerini koruyun ve arşivleme politikanıza göre damgalama planlayın.", "INFO"));
        }
        if (!wrapper.isTrustedChain()) {
            result.add(recommendation("TRUST_CHAIN_INCOMPLETE", "Güven zincirini inceleyin",
                    "DSS, güvenilir köke ulaşan bir sertifika zinciri bildirmedi. Ara sertifikaları ve etkin güven deposunu kontrol edin.", "WARNING"));
        }
        if (info.getChainRevocationStatus() == ChainRevocationStatus.NOT_CHECKED
                || info.getChainRevocationStatus() == ChainRevocationStatus.UNKNOWN) {
            result.add(recommendation("REVOCATION_EVIDENCE_MISSING", "İptal kanıtlarını tamamlayın",
                    "Zincirin iptal durumu kesinleştirilemedi. İlgili OCSP/SİL kanıtlarını ve çevrimiçi erişimi inceleyin.", "WARNING"));
        }
        if (info.getTimestamps() != null) {
            for (TimestampInfo timestamp : info.getTimestamps()) {
                if (!timestamp.isValid() || timestamp.getIndication() == null) {
                    result.add(recommendation("TIMESTAMP_VALIDATION_INCOMPLETE", "Zaman damgası kanıtını inceleyin",
                            "En az bir zaman damgasının tam doğrulama sonucu başarılı değil veya mevcut değil. Damga özeti, TSA zinciri ve DSS sonucunu inceleyin.", "WARNING"));
                    break;
                }
            }
        }
        for (SignedReferenceInfo reference : info.getSignedReferences()) {
            if (!reference.isDataFound() || !reference.isDataIntact() || reference.isDuplicated()) {
                result.add(recommendation("SIGNED_REFERENCE_INCOMPLETE", "İmzalı içerik eşleşmesini inceleyin",
                        "DSS en az bir imza referansını eksik, değiştirilmiş veya yinelenmiş olarak bildirdi. Ayrık imzanın özgün belgesini ve referans ayrıntılarını kontrol edin.", "WARNING"));
                break;
            }
        }
        return result;
    }

    private static VerificationRecommendation recommendation(String code, String title, String description, String severity) {
        VerificationRecommendation value = new VerificationRecommendation();
        value.setCode(code);
        value.setTitle(title);
        value.setDescription(description);
        value.setSeverity(severity);
        return value;
    }
}
