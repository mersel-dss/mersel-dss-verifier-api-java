package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

/** DSS digest matcher evidence for one signed reference; digestValue is base64. A found/intact reference alone does not establish signature validity. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignedReferenceInfo {
    /** DSS digest matcher evidence for one signed reference; digestValue is base64. A found/intact reference alone does not establish signature validity. */
    private String id;
    private String uri;
    private String documentName;
    private String type;
    private String digestAlgorithm;
    private String digestValue;
    private boolean dataFound;
    private boolean dataIntact;
    private boolean duplicated;


    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getUri() { return uri; }
    public void setUri(String uri) { this.uri = uri; }

    public String getDocumentName() { return documentName; }
    public void setDocumentName(String documentName) { this.documentName = documentName; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getDigestAlgorithm() { return digestAlgorithm; }
    public void setDigestAlgorithm(String digestAlgorithm) { this.digestAlgorithm = digestAlgorithm; }

    public String getDigestValue() { return digestValue; }
    public void setDigestValue(String digestValue) { this.digestValue = digestValue; }

    public boolean isDataFound() { return dataFound; }
    public void setDataFound(boolean dataFound) { this.dataFound = dataFound; }

    public boolean isDataIntact() { return dataIntact; }
    public void setDataIntact(boolean dataIntact) { this.dataIntact = dataIntact; }

    public boolean isDuplicated() { return duplicated; }
    public void setDuplicated(boolean duplicated) { this.duplicated = duplicated; }
}
