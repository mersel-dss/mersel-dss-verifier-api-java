package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.mersel.dss.verify.api.controllers.*;
import io.mersel.dss.verify.api.GlobalExceptionHandler;
import io.mersel.dss.verify.api.exceptions.TrustConflictException;
import io.mersel.dss.verify.api.models.*;
import io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.http.MediaType;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ActiveTrustStoreTest {
    static CertificateToken a, b;
    ActiveTrustStore store;
    CommonTrustedCertificateSource configured;
    @BeforeAll static void certificates() throws Exception {
        a = RequestTrustFactoryTest.certificate("Active A"); b = RequestTrustFactoryTest.certificate("Active B");
    }
    @BeforeEach void setup() {
        store = new ActiveTrustStore(); configured = new CommonTrustedCertificateSource(); configured.addCertificate(a);
    }
    RequestTrustContext current() { return store.snapshot(() -> configured); }
    RequestTrustContext custom(CertificateToken... tokens) { return new RequestTrustContext("CUSTOM", Arrays.asList(tokens)); }
    @Test void activationSurvivesRepeatedRequestsAndResolverRefreshAndAllowsEmpty() {
        RequestTrustContext before = current();
        RequestTrustContext active = store.replace(before.getActiveTrustId(), custom(b), Collections.emptyList(), () -> configured);
        configured.addCertificate(b); // background standard resolver refresh cannot affect CUSTOM
        for (int i=0; i<10; i++) {
            assertEquals(active.getActiveTrustId(), current().getActiveTrustId());
            assertEquals(Collections.singletonList(b), current().newSource().getCertificates());
        }
        store.replace(active.getActiveTrustId(), custom(), Collections.emptyList(), () -> configured);
        assertTrue(current().isCustom()); assertEquals(0, current().evidence(false).getCertificateCount());
        assertEquals(Collections.singletonList(a), before.newSource().getCertificates(), "In-flight snapshot stays on old roots");
        RequestTrustContext reset = store.replace(current().getActiveTrustId(), null, Collections.emptyList(), () -> configured);
        assertFalse(reset.isCustom()); assertEquals(2, reset.evidence(false).getCertificateCount());
    }
    @Test void retainsOnlySelectedExistingRootsAndAddsNewOnesWithoutReuploadingOldCertificates() {
        store.replace(current().getActiveTrustId(), custom(a,b), Collections.emptyList(), () -> configured);
        String keep = new RequestTrustContext("CUSTOM", Collections.singletonList(b)).evidence(false).getAnchors().get(0).getSha256();
        store.replace(current().getActiveTrustId(), custom(), Collections.singletonList(keep), () -> configured);
        assertEquals(Collections.singletonList(b), current().newSource().getCertificates());
        String id = current().getActiveTrustId();
        assertThrows(IllegalArgumentException.class, () -> store.replace(id, custom(a), Collections.singletonList("missing"), () -> configured));
        assertEquals(id, current().getActiveTrustId());
    }
    @Test void canKeepSelectedConfiguredRootsWithoutDownloadingTheirCertificateBytes() {
        configured.addCertificate(b);
        String keep = custom(b).evidence(false).getAnchors().get(0).getSha256();
        store.replace(current().getActiveTrustId(), custom(), Collections.singletonList(keep), () -> configured);
        assertTrue(current().isCustom());
        assertEquals(Collections.singletonList(b), current().newSource().getCertificates());
        assertEquals(2, configured.getCertificates().size());
    }
    @Test void staleEditorsAndRestartIdsCannotOverwriteCurrentState() {
        String original = current().getActiveTrustId();
        store.replace(original, custom(b), Collections.emptyList(), () -> configured);
        assertThrows(TrustConflictException.class, () -> store.replace(original, custom(a), Collections.emptyList(), () -> configured));
        ActiveTrustStore restarted = new ActiveTrustStore();
        assertFalse(restarted.snapshot(() -> configured).isCustom());
        assertNotEquals(current().getActiveTrustId(), restarted.snapshot(() -> configured).getActiveTrustId());
        assertThrows(TrustConflictException.class, () -> restarted.replace(current().getActiveTrustId(), custom(b), Collections.emptyList(), () -> configured));
    }
    @Test void concurrentReadersSeeCompleteOldOrNewSnapshots() throws Exception {
        store.replace(current().getActiveTrustId(), custom(a), Collections.emptyList(), () -> configured);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int i=0;i<3;i++) tasks.add(() -> { for(int n=0;n<100;n++) {
                RequestTrustContext snapshot = current();
                List<CertificateToken> tokens = snapshot.newSource().getCertificates();
                if(tokens.size()!=1 || (!tokens.get(0).equals(a) && !tokens.get(0).equals(b))) return false;
                if(!snapshot.evidence(false).getActiveTrustId().equals(snapshot.getActiveTrustId())) return false;
            } return true; });
            tasks.add(() -> { for(int n=0;n<30;n++) store.replace(current().getActiveTrustId(), custom(n%2==0?a:b), Collections.emptyList(), () -> configured); return true; });
            for(Future<Boolean> result:pool.invokeAll(tasks)) assertTrue(result.get());
        } finally { pool.shutdownNow(); }
    }
    KamusmRootCertificateService roots() {
        TrustedRootCertificateResolver resolver = mock(TrustedRootCertificateResolver.class);
        when(resolver.getTrustedCertificateSource()).thenReturn(configured);
        KamusmRootCertificateService roots = new KamusmRootCertificateService("folder",resolver,resolver,resolver);
        ReflectionTestUtils.setField(roots,"activeTrustStore",store); return roots;
    }
    @Test void httpActivationPersistsAndStaleVerificationIsRejectedBeforeTheEngine() throws Exception {
        KamusmRootCertificateService roots = roots();
        RequestTrustFactory factory = new RequestTrustFactory(true);
        AdvancedSignatureVerificationService engine = mock(AdvancedSignatureVerificationService.class);
        when(engine.verifySignature(any(),any(),any(),anyBoolean())).thenAnswer(call -> {
            VerificationResult result=new VerificationResult(false,"NO_SIGNATURE_FOUND"); result.setTrustContext(roots.getVerificationTrustContext().evidence(false)); return result;
        });
        UnifiedVerificationController verify = new UnifiedVerificationController();
        ReflectionTestUtils.setField(verify,"requestTrustFactory",factory);
        ReflectionTestUtils.setField(verify,"rootCertificateService",roots);
        ReflectionTestUtils.setField(verify,"advancedSignatureVerificationService",engine);
        MockMvc mvc=MockMvcBuilders.standaloneSetup(new ActiveTrustController(store,roots,factory,false),verify)
            .setControllerAdvice(new GlobalExceptionHandler()).build();
        String old=current().getActiveTrustId();
        mvc.perform(multipart("/api/v1/trust/active")
            .file(new MockMultipartFile("trustedCertificates","b.cer","application/pkix-cert",b.getEncoded())).param("mode","CUSTOM").param("expectedTrustId",old).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk()).andExpect(jsonPath("$.mode").value("CUSTOM")).andExpect(jsonPath("$.certificateCount").value(1));
        String id=current().getActiveTrustId();
        mvc.perform(get("/api/v1/trust/active").accept(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.activeTrustId").value(id)).andExpect(jsonPath("$.anchors[0].derBase64").doesNotExist());
        for(int i=0;i<2;i++) mvc.perform(multipart("/api/v1/verify/signature")
            .file(new MockMultipartFile("signedDocument","test.xml","text/xml","<test/>".getBytes())).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk()).andExpect(jsonPath("$.trustContext.activeTrustId").value(id));
        mvc.perform(multipart("/api/v1/verify/signature")
            .file(new MockMultipartFile("signedDocument","test.xml","text/xml","<test/>".getBytes())).param("expectedTrustId",old).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("TRUST_CHANGED"));
        verify(engine,never()).verifySignature(any(),any(),any(),anyBoolean(),any());
        mvc.perform(multipart("/api/v1/trust/active")
            .file(new MockMultipartFile("trustedCertificates","bad.cer","application/pkix-cert",new byte[]{1})).param("mode","CUSTOM").param("expectedTrustId",id).accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest());
        assertEquals(id,current().getActiveTrustId());
    }
    @Test void disabledActivationCannotChangeState() throws Exception {
        String id=current().getActiveTrustId();
        MockMvc mvc=MockMvcBuilders.standaloneSetup(new ActiveTrustController(store,roots(),new RequestTrustFactory(false),false))
            .setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(multipart("/api/v1/trust/active").param("mode","CUSTOM").param("expectedTrustId",id)).andExpect(status().isBadRequest());
        assertEquals(id,current().getActiveTrustId());
    }
}
