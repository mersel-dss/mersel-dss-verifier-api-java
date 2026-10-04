package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import io.mersel.dss.verify.api.exceptions.PolicyActivationException;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Locale;
import java.util.Set;

/**
 * Arayüzden gönderilen özel politika XML'ini etkinleştirmeden önce doğrular.
 *
 * <ol>
 *   <li>XXE-güvenli SAX ayrıştırma: DOCTYPE (dolayısıyla ENTITY) bildirimi reddedilir,
 *       harici varlık/DTD yüklemesi kapalı, iyi biçimlendirilmiş olmalı.</li>
 *   <li>Doğrulamanın kullandığı DSS API'si ile yükleme
 *       ({@code SignedDocumentValidator#validateDocument(InputStream)} ile aynı yol:
 *       {@link ValidationPolicyLoader#fromValidationPolicy(eu.europa.esig.dss.model.DSSDocument)}).
 *       DSS {@code ConstraintsParameters} XSD şema doğrulamasıyla unmarshal eder.</li>
 * </ol>
 */
final class PolicyXmlValidator {
    private static final int MAX_DETAIL_LENGTH = 400;

    private PolicyXmlValidator() {
    }

    static void validate(byte[] xml) {
        requireWellFormedWithoutDtd(xml);
        try {
            ValidationPolicyLoader.fromValidationPolicy(new InMemoryDocument(xml)).create();
        } catch (Exception e) {
            throw PolicyActivationException.invalid("Politika XML'i DSS doğrulama politikası olarak yüklenemedi "
                    + "(ConstraintsParameters şeması): " + describe(e));
        }
    }

    private static void requireWellFormedWithoutDtd(byte[] xml) {
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setValidating(false);
            factory.setXIncludeAware(false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.newSAXParser().parse(new ByteArrayInputStream(xml), new DefaultHandler());
        } catch (SAXParseException e) {
            String message = e.getMessage() == null ? "" : e.getMessage();
            if (message.toUpperCase(Locale.ROOT).contains("DOCTYPE")) {
                throw PolicyActivationException.invalid("Politika XML'i DOCTYPE/ENTITY bildirimi içeremez "
                        + "(DTD ve harici varlıklar güvenlik nedeniyle kabul edilmez).");
            }
            throw PolicyActivationException.invalid("Politika XML'i iyi biçimlendirilmemiş (satır "
                    + e.getLineNumber() + ", sütun " + e.getColumnNumber() + "): " + truncate(message));
        } catch (SAXException | IOException e) {
            throw PolicyActivationException.invalid("Politika XML'i okunamadı: " + truncate(String.valueOf(e.getMessage())));
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Güvenli XML ayrıştırıcısı yapılandırılamadı", e);
        }
    }

    /** DSS/JAXB hata zincirinden kullanıcıya gösterilebilir en spesifik nedeni çıkarır. */
    private static String describe(Throwable error) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        String message = null;
        for (Throwable cursor = error; cursor != null && seen.add(cursor); cursor = cursor.getCause()) {
            if (cursor instanceof SAXParseException) {
                SAXParseException parse = (SAXParseException) cursor;
                return "satır " + parse.getLineNumber() + ", sütun " + parse.getColumnNumber() + ": "
                        + truncate(String.valueOf(parse.getMessage()));
            }
            if (cursor.getMessage() != null && !cursor.getMessage().trim().isEmpty()) message = cursor.getMessage();
        }
        if (message == null) return error.getClass().getSimpleName();
        if (message.startsWith("The validation policy is not valid or no suitable ValidationPolicyFactory")) {
            return "kök öğe http://dss.esig.europa.eu/validation/policy ad alanındaki ConstraintsParameters olmalıdır";
        }
        return truncate(message);
    }

    private static String truncate(String value) {
        return value.length() <= MAX_DETAIL_LENGTH ? value : value.substring(0, MAX_DETAIL_LENGTH) + "…";
    }
}
