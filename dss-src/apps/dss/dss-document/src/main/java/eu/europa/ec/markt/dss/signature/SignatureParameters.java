/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Parameters for a Signature creation/extension
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignatureParameters {

    private Date signingDate;

    private X509Certificate signingCertificate;

    private List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();

    private SignaturePolicy signaturePolicy = SignaturePolicy.NO_POLICY;

    private String signaturePolicyId;

    private String signaturePolicyHashAlgo;

    private byte[] signaturePolicyHashValue;

    private String claimedSignerRole;

    private SignatureFormat signatureFormat;

    private SignaturePackaging signaturePackaging;
    
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA;
    
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
    
    private String reason;
    
    private String contactInfo;
    
    private String location;
    
    private List<String> commitmentTypeIndication;
    
    /**
     * Get the signing certificate
     * 
     * @return
     */
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Set the signing certificate
     * 
     * @param signingCertificate
     */
    public void setSigningCertificate(X509Certificate signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    /**
     * Set the signing date
     * 
     * @param signingDate
     */
    public void setSigningDate(Date signingDate) {
        this.signingDate = signingDate;
    }

    /**
     * Get the signing date
     * 
     * @return
     */
    public Date getSigningDate() {
        return signingDate;
    }

    /**
     * Set the certificate chain
     * 
     * @return
     */
    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    /**
     * Get the certificate chain
     * 
     * @param certificateChain
     */
    public void setCertificateChain(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * 
     * @param certificateChain
     */
    public void setCertificateChain(Certificate... certificateChain) {
        List<X509Certificate> list = new ArrayList<X509Certificate>();
        for (Certificate c : certificateChain) {
            list.add((X509Certificate) c);
        }
        this.certificateChain = list;
    }

    /**
     * Get the signature policy (EPES)
     * 
     * @return
     */
    public String getSignaturePolicyId() {
        return signaturePolicyId;
    }

    /**
     * Set the signature policy (EPES)
     * 
     * @param signaturePolicyId
     */
    public void setSignaturePolicyId(String signaturePolicyId) {
        this.signaturePolicyId = signaturePolicyId;
    }

    /**
     * Get claimed role
     * 
     * @return
     */
    public String getClaimedSignerRole() {
        return claimedSignerRole;
    }

    /**
     * Set claimed role
     * 
     * @param claimedSignerRole
     */
    public void setClaimedSignerRole(String claimedSignerRole) {
        this.claimedSignerRole = claimedSignerRole;
    }

    /**
     * Get signature format
     * 
     * @return
     */
    public SignatureFormat getSignatureFormat() {
        return signatureFormat;
    }

    /**
     * Set signature format
     * 
     * @param signatureFormat
     * @deprecated Use the SignatureFormat enumeration instead
     */
    public void setSignatureFormat(String signatureFormat) {
        setSignatureFormat(SignatureFormat.valueByName(signatureFormat));
    }

    /**
     * Set signature format
     * 
     * @param signatureFormat
     */
    public void setSignatureFormat(SignatureFormat signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    /**
     * Get Signature packaging
     * 
     * @return
     */
    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    /**
     * Set Signature packaging
     * 
     * @param signaturePackaging
     */
    public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    /**
     * Return the type of signature policy
     * 
     * @return
     */
    public SignaturePolicy getSignaturePolicy() {
        return signaturePolicy;
    }

    /**
     * Set the type of signature policy
     * 
     * @param signaturePolicy
     */
    public void setSignaturePolicy(SignaturePolicy signaturePolicy) {
        this.signaturePolicy = signaturePolicy;
    }

    /**
     * Return the hash algorithm for the signature policy
     * 
     * @return
     */
    public String getSignaturePolicyHashAlgo() {
        return signaturePolicyHashAlgo;
    }

    /**
     * Set the hash algorithm for the explicit signature policy
     * 
     * @param signaturePolicyHashAlgo
     */
    public void setSignaturePolicyHashAlgo(String signaturePolicyHashAlgo) {
        this.signaturePolicyHashAlgo = signaturePolicyHashAlgo;
    }

    /**
     * Get the hash value of the explicit signature policy
     * 
     * @return
     */
    public byte[] getSignaturePolicyHashValue() {
        return signaturePolicyHashValue;
    }

    /**
     * Set the hash value of implicit signature policy
     * 
     * @param signaturePolicyHashValue
     */
    public void setSignaturePolicyHashValue(byte[] signaturePolicyHashValue) {
        this.signaturePolicyHashValue = signaturePolicyHashValue;
    }

    /**
     * @return the digestAlgorithm
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @param digestAlgorithm the digestAlgorithm to set
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * @return the reason
     */
    public String getReason() {
        return reason;
    }

    /**
     * @param reason the reason to set
     */
    public void setReason(String reason) {
        this.reason = reason;
    }

    /**
     * @return the contactInfo
     */
    public String getContactInfo() {
        return contactInfo;
    }

    /**
     * @param contactInfo the contactInfo to set
     */
    public void setContactInfo(String contactInfo) {
        this.contactInfo = contactInfo;
    }

    /**
     * @return the location
     */
    public String getLocation() {
        return location;
    }

    /**
     * @param location the location to set
     */
    public void setLocation(String location) {
        this.location = location;
    }

    /**
     * @return the commitmentTypeIndication
     */
    public List<String> getCommitmentTypeIndication() {
        return commitmentTypeIndication;
    }

    /**
     * @param commitmentTypeIndication the commitmentTypeIndication to set
     */
    public void setCommitmentTypeIndication(List<String> commitmentTypeIndication) {
        this.commitmentTypeIndication = commitmentTypeIndication;
    }

    /**
     * @return the signatureAlgorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

}
