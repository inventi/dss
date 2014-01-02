package eu.europa.ec.markt.dss.validation.report;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import java.util.Date;

import org.bouncycastle.cms.SignerInformation;

/**
 * Validation information of a timestamp.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class TimestampVerificationResult {

    private Result sameDigest;
    private Result certPathVerification = new Result();
    private String signatureAlgorithm;
    private String serialNumber;
    private Date creationTime;
    private String issuerName;

    /**
     * The default constructor for TimestampVerificationResult.
     */
    public TimestampVerificationResult() {
    }
    
    /**
     * The default constructor for TimestampVerificationResult.
     */
    public TimestampVerificationResult(TimestampToken token) {
        if (token != null && token.getTimeStamp() != null) {
            signatureAlgorithm = ((SignerInformation) token.getTimeStamp().toCMSSignedData()
                    .getSignerInfos().getSigners().iterator().next()).getEncryptionAlgOID();
            serialNumber = token.getTimeStamp().getTimeStampInfo().getSerialNumber().toString();
            creationTime = token.getTimeStamp().getTimeStampInfo().getGenTime();
            // Inventi BUG-FIX: do not fail with NPE on timestamps without certificates
            X500Principal issuer = token.getSignerSubjectName();
            if (issuer != null) {
                issuerName = issuer.toString();
            }
        }
    }

    /**
     * @param sameDigest the sameDigest to set
     */
    public void setSameDigest(Result sameDigest) {
        this.sameDigest = sameDigest;
    }

    /**
     * @return the sameDigest
     */
    public Result getSameDigest() {
        return sameDigest;
    }

    /**
     * 
     * @return
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * 
     * @return
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * 
     * @return
     */
    public Date getCreationTime() {
        return creationTime;
    }

    /**
     * 
     * @return
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * 
     * @return
     */
    public Result getCertPathUpToTrustedList() {
        return certPathVerification;
    }

    /**
     * @return the certPathVerification
     */
    public Result getCertPathVerification() {
        return certPathVerification;
    }

    /**
     * @param certPathVerification the certPathVerification to set
     */
    public void setCertPathVerification(Result certPathVerification) {
        this.certPathVerification = certPathVerification;
    }

    /**
     * @param signatureAlgorithm the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @param serialNumber the serialNumber to set
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @param creationTime the creationTime to set
     */
    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * @param issuerName the issuerName to set
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

}
