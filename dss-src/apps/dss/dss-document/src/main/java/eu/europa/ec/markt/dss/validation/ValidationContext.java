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

package eu.europa.ec.markt.dss.validation;

import eu.europa.ec.markt.dss.signature.SignatureEventDelegate;
import eu.europa.ec.markt.dss.signature.SignatureEventListener;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.certificate.CompositeCertificateSource;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.crl.ListCRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.ListOCSPSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation.tsl.ServiceInfo;
import eu.europa.ec.markt.dss.validation.x509.CRLToken;
import eu.europa.ec.markt.dss.validation.x509.CertificateToken;
import eu.europa.ec.markt.dss.validation.x509.OCSPRespToken;
import eu.europa.ec.markt.dss.validation.x509.RevocationData;
import eu.europa.ec.markt.dss.validation.x509.SignedToken;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.SingleResp;

/**
 * During the validation of a certificate, the software retrieve differents X509 artifact like Certificate, CRL and OCSP
 * Response. The ValidationContext is a "cache" for one validation request that contains every object retrieved so far.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class ValidationContext {

    private static final Logger LOG = Logger.getLogger(ValidationContext.class.getName());

    private List<BasicOCSPResp> neededOCSPResp = new ArrayList<BasicOCSPResp>();

    private List<X509CRL> neededCRL = new ArrayList<X509CRL>();

    private List<CertificateAndContext> neededCertificates = new ArrayList<CertificateAndContext>();

    private X509Certificate certificate;

    private Map<SignedToken, RevocationData> revocationInfo = new HashMap<SignedToken, RevocationData>();

    private CertificateSource trustedListCertificatesSource;

    private OCSPSource ocspSource;

    private CRLSource crlSource;

    private Date validationDate;

    private SignatureEventDelegate signatureEventDelegate = new SignatureEventDelegate();

    /**
     * 
     * The default constructor for ValidationContextV2.
     * 
     * @param certificate The certificate that will be validated.
     */
    public ValidationContext(X509Certificate certificate, Date validationDate) {
        if (certificate != null) {
            LOG.info("New context for " + certificate.getSubjectDN());
            this.certificate = certificate;
            addNotYetVerifiedToken(new CertificateToken(new CertificateAndContext(certificate)));
        }
        this.validationDate = validationDate;
    }

    /**
     * Return the certificate for which this ValidationContext has been created
     * 
     * @return the certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * @return the validationDate
     */
    public Date getValidationDate() {
        return validationDate;
    }

    /**
     * @param trustedListCertificatesSource the trustedListCertificatesSource to set
     */
    public void setTrustedListCertificatesSource(CertificateSource trustedListCertificatesSource) {
        this.trustedListCertificatesSource = trustedListCertificatesSource;
    }

    /**
     * @param crlSource the crlSource to set
     */
    public void setCrlSource(CRLSource crlSource) {
        this.crlSource = crlSource;
    }

    /**
     * @param ocspSource the ocspSource to set
     */
    public void setOcspSource(OCSPSource ocspSource) {
        this.ocspSource = ocspSource;
    }

    SignedToken getOneNotYetVerifiedToken() {
        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {
            if (e.getValue() == null) {
                LOG.info("=== Get token to validate " + e.getKey());
                return e.getKey();
            }
        }
        return null;
    }

    /**
     * 
     * @param signedToken
     * @param optionalSource
     * @param validationDate
     * @return
     * @throws IOException An error occurs when accessing the CertificateSource
     */
    CertificateAndContext getIssuerCertificate(SignedToken signedToken, CertificateSource optionalSource,
            Date validationDate) throws IOException {
        if (signedToken.getSignerSubjectName() == null) {
            return null;
        }
        List<CertificateAndContext> list = new CompositeCertificateSource(trustedListCertificatesSource,
                optionalSource).getCertificateBySubjectName(signedToken.getSignerSubjectName());
        if (list != null) {
            for (CertificateAndContext cert : list) {
                LOG.info(cert.toString());
                /* If there is a validation date, we skip the issuer */
                if (validationDate != null) {
                    try {
                        cert.getCertificate().checkValidity(validationDate);
                    } catch (CertificateExpiredException e) {
                        LOG.info("Was expired");
                        continue;
                    } catch (CertificateNotYetValidException e) {
                        LOG.info("Was not yet valid");
                        continue;
                    }
                    if (cert.getCertificateSource() == CertificateSourceType.TRUSTED_LIST
                            && cert.getContext() != null) {
                        ServiceInfo info = (ServiceInfo) cert.getContext();
                        if (info.getStatusStartingDateAtReferenceTime() != null
                                && validationDate.before(info.getStatusStartingDateAtReferenceTime())) {
                            LOG.info("Was not valid in the TSL");
                            continue;
                        } else if (info.getStatusEndingDateAtReferenceTime() != null
                                && validationDate.after(info.getStatusEndingDateAtReferenceTime())) {
                            LOG.info("Was not valid in the TSL");
                            continue;
                        }
                    }
                }
                /* We keep the first issuer that sign the certificate */
                if (signedToken.isSignedBy(cert.getCertificate())) {
                    return cert;
                }
            }
        }
        return null;
    }

    void addNotYetVerifiedToken(SignedToken signedToken) {

        if (!revocationInfo.containsKey(signedToken)) {
            LOG.info("New token to validate " + signedToken + " hashCode " + signedToken.hashCode());
            revocationInfo.put(signedToken, null);

            if (signedToken instanceof CRLToken) {
                neededCRL.add(((CRLToken) signedToken).getX509crl());
            } else if (signedToken instanceof OCSPRespToken) {
                neededOCSPResp.add(((OCSPRespToken) signedToken).getOcspResp());
            } else if (signedToken instanceof CertificateToken) {
                boolean found = false;
                CertificateAndContext newCert = ((CertificateToken) signedToken).getCertificateAndContext();
                for (CertificateAndContext c : neededCertificates) {
                    if (c.getCertificate().equals(newCert.getCertificate())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    neededCertificates.add(newCert);
                }
            }

        } else {
            LOG.info("Token was already in list " + signedToken);
        }

    }

    void validate(SignedToken signedToken, RevocationData data) {
        if (data == null) {
            throw new IllegalArgumentException("data cannot be null");
        }
        if (!revocationInfo.containsKey(signedToken)) {
            throw new IllegalArgumentException(signedToken + " must be a key of revocationInfo");
        }

        revocationInfo.put(signedToken, data);
    }

    /**
     * Validate the timestamp
     * 
     * @param timestamp
     * @param optionalSource
     * @param optionalCRLSource
     * @param optionalOCPSSource
     */
    public void validateTimestamp(TimestampToken timestamp, CertificateSource optionalSource,
            CRLSource optionalCRLSource, OCSPSource optionalOCPSSource) throws IOException {
        addNotYetVerifiedToken(timestamp);
        validate(timestamp.getTimeStamp().getTimeStampInfo().getGenTime(),
                new CompositeCertificateSource(timestamp.getWrappedCertificateSource(), optionalSource),
                optionalCRLSource, optionalOCPSSource);
    }

    /**
     * Build the validation context for the specific date
     * 
     * @param validationDate
     * @param optionalSource
     */
    public void validate(Date validationDate, CertificateSource optionalSource, CRLSource optionalCRLSource,
            OCSPSource optionalOCPSSource) throws IOException {

        int previousSize = revocationInfo.size();
        int previousVerified = verifiedTokenCount();

        SignedToken signedToken = getOneNotYetVerifiedToken();
        if (signedToken != null) {

            CertificateSource otherSource = optionalSource;
            if (signedToken != null) {
                otherSource = new CompositeCertificateSource(signedToken.getWrappedCertificateSource(),
                        optionalSource);
            }

            CertificateAndContext issuer = getIssuerCertificate(signedToken, otherSource, validationDate);

            RevocationData data = null;

            if (issuer == null) {
                /* We don't find an issuer, so the RevocationData cannot be retrieved. */
                LOG.warning("Don't found any issuer for token " + signedToken);
                data = new RevocationData(signedToken);
            } else {

                addNotYetVerifiedToken(new CertificateToken(issuer));

                if (issuer.getCertificate().getSubjectX500Principal()
                        .equals(issuer.getCertificate().getIssuerX500Principal())) {
                    SignedToken trustedToken = new CertificateToken(issuer);
                    RevocationData noNeedToValidate = new RevocationData();
                    // noNeedToValidate.setRevocationData(CertificateSourceType.TRUSTED_LIST);
                    validate(trustedToken, noNeedToValidate);
                }

                if (issuer.getCertificateSource() == CertificateSourceType.TRUSTED_LIST) {
                    SignedToken trustedToken = new CertificateToken(issuer);
                    RevocationData noNeedToValidate = new RevocationData();
                    noNeedToValidate.setRevocationData(CertificateSourceType.TRUSTED_LIST);
                    validate(trustedToken, noNeedToValidate);
                }

                if (signedToken instanceof CertificateToken) {

                    CertificateToken ct = (CertificateToken) signedToken;
                    CertificateStatus status = getCertificateValidity(ct.getCertificateAndContext(), issuer,
                            validationDate, optionalCRLSource, optionalOCPSSource);
                    data = new RevocationData(signedToken);
                    if (status != null) {
                        data.setRevocationData(status.getStatusSource());

                        if (status.getStatusSource() instanceof X509CRL) {
                            addNotYetVerifiedToken(new CRLToken((X509CRL) status.getStatusSource()));
                        } else if (status.getStatusSource() instanceof BasicOCSPResp) {
                            addNotYetVerifiedToken(new OCSPRespToken((BasicOCSPResp) status.getStatusSource()));
                        }

                    } else {
                        LOG.warning("No status for " + signedToken);
                    }

                } else if (signedToken instanceof CRLToken || signedToken instanceof OCSPRespToken
                        || signedToken instanceof TimestampToken) {

                    data = new RevocationData(signedToken);
                    data.setRevocationData(issuer);

                } else {
                    throw new RuntimeException("Not supported token type " + signedToken.getClass().getSimpleName());
                }

            }

            validate(signedToken, data);

            LOG.info(this.toString());

            int newSize = revocationInfo.size();
            int newVerified = verifiedTokenCount();

            if (newSize != previousSize || newVerified != previousVerified) {
                validate(validationDate, otherSource, optionalCRLSource, optionalOCPSSource);
            }
        }

    }

    int verifiedTokenCount() {
        int count = 0;
        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {
            if (e.getValue() != null) {
                count++;
            }
        }
        return count;
    }

    @Override
    public String toString() {
        int count = 0;
        StringBuilder builder = new StringBuilder();
        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {
            if (e.getValue() != null) {
                builder.append(e.getValue());
                count++;
            } else {
                builder.append(e.getKey());
            }
            builder.append(" ");
        }
        return "ValidationContext contains " + revocationInfo.size() + " SignedToken and " + count
                + " of them have been verified. List : " + builder.toString();
    }

    private CertificateStatus getCertificateValidity(CertificateAndContext cert,
            CertificateAndContext potentialIssuer, Date validationDate, CRLSource optionalCRLSource,
            OCSPSource optionalOCSPSource) {

        if (optionalCRLSource != null || optionalOCSPSource != null) {
            LOG.info("Verify with offline services");
            OCSPAndCRLCertificateVerifier verifier = new OCSPAndCRLCertificateVerifier();
            verifier.setCrlSource(optionalCRLSource);
            verifier.setOcspSource(optionalOCSPSource);
            CertificateStatus status = verifier.check(cert.getCertificate(), potentialIssuer.getCertificate(),
                    validationDate);
            if (status != null) {
                return status;
            }
        }

        LOG.info("Verify with online services");
        OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier();
        onlineVerifier.setCrlSource(crlSource);
        onlineVerifier.setOcspSource(ocspSource);

        return onlineVerifier.check(cert.getCertificate(), potentialIssuer.getCertificate(), validationDate);

    }

    /**
     * @return the neededCRL
     */
    public List<X509CRL> getNeededCRL() {
        return neededCRL;
    }

    /**
     * @return the neededOCSPResp
     */
    public List<BasicOCSPResp> getNeededOCSPResp() {
        return neededOCSPResp;
    }

    /**
     * @return the neededCertificates
     */
    public List<CertificateAndContext> getNeededCertificates() {
        return neededCertificates;
    }

    /**
     * Finds the provided certificate's issuer in the context
     * 
     * @param cert The certificate whose issuer to find
     * @return the issuer's X509Certificate
     */
    public CertificateAndContext getIssuerCertificateFromThisContext(CertificateAndContext cert) {

        /* Don't search for parent of self signed certificate */
        if (cert.getCertificate().getSubjectDN().equals(cert.getCertificate().getIssuerDN())) {
            return null;
        }

        /* Ideally we should verify more thoroughly (i.e. with the signature) here */
        for (CertificateAndContext c : neededCertificates) {
            if (c.getCertificate().getSubjectX500Principal().equals(cert.getCertificate().getIssuerX500Principal())) {
                return c;
            }
        }

        return null;
    }

    private boolean concernsCertificate(X509CRL x509crl, CertificateAndContext cert) {
        return (x509crl.getIssuerX500Principal().equals(cert.getCertificate().getIssuerX500Principal()));
    }

    private boolean concernsCertificate(BasicOCSPResp basicOcspResp, CertificateAndContext cert) {
        CertificateAndContext issuerCertificate = getIssuerCertificateFromThisContext(cert);
        if (issuerCertificate == null) {
            return false;
        } else {
            try {
                CertificateID matchingCertID = new CertificateID(CertificateID.HASH_SHA1,
                        issuerCertificate.getCertificate(), cert.getCertificate().getSerialNumber());
                for (SingleResp resp : basicOcspResp.getResponses()) {
                    if (resp.getCertID().equals(matchingCertID)) {
                        return true;
                    }
                }
                return false;
            } catch (OCSPException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    /**
     * Returns the CRLs in the context which concern the provided certificate. It can happen there are more than one,
     * even though this is unlikely.
     * 
     * @param cert the X509 certificate
     * @return the list of CRLs related to the certificate
     */
    public List<X509CRL> getRelatedCRLs(CertificateAndContext cert) {
        List<X509CRL> crls = new ArrayList<X509CRL>();
        for (X509CRL crl : this.neededCRL) {
            if (concernsCertificate(crl, cert)) {
                crls.add(crl);
            }
        }

        return crls;
    }

    /**
     * Returns the OCSP responses in the context which concern the provided certificate. It can happen there are more
     * than one, even though this is unlikely.
     * 
     * @param cert the X509 certificate
     * @return the list of OCSP responses related to the certificate
     * @throws OCSPException
     */
    public List<BasicOCSPResp> getRelatedOCSPResp(CertificateAndContext cert) {
        List<BasicOCSPResp> ocspresps = new ArrayList<BasicOCSPResp>();
        for (BasicOCSPResp ocspresp : this.neededOCSPResp) {
            if (this.concernsCertificate(ocspresp, cert)) {
                ocspresps.add(ocspresp);
            }
        }
        return ocspresps;
    }

    /**
     * 
     * @param cert
     * @return
     */
    public CertificateStatus getCertificateStatusFromContext(CertificateAndContext cert) {

        if (cert.getCertificateSource() == CertificateSourceType.TRUSTED_LIST) {
            CertificateStatus status = new CertificateStatus();
            status.setValidity(CertificateValidity.VALID);
            status.setStatusSourceType(ValidatorSourceType.TRUSTED_LIST);
            status.setCertificate(cert.getCertificate());
            return status;
        }

        CertificateAndContext issuer = getIssuerCertificateFromThisContext(cert);
        if (issuer == null) {
            return null;
        }

        OCSPSource ocspSource = new ListOCSPSource(neededOCSPResp);
        CRLSource crlSource = new ListCRLSource(neededCRL);
        OCSPAndCRLCertificateVerifier verifier = new OCSPAndCRLCertificateVerifier();
        verifier.setCrlSource(crlSource);
        verifier.setOcspSource(ocspSource);
        return verifier.check(cert.getCertificate(), issuer.getCertificate(), getValidationDate());
    }

    /**
     * Retrieve the parent from the trusted list
     * 
     * @param ctx
     * @return
     */
    public CertificateAndContext getParentFromTrustedList(CertificateAndContext ctx) {

        CertificateAndContext parent = ctx;
        while (getIssuerCertificateFromThisContext(parent) != null) {
            parent = getIssuerCertificateFromThisContext(parent);
            if (parent.getCertificateSource() == CertificateSourceType.TRUSTED_LIST) {
                LOG.info("Parent from TrustedList found " + parent);
                return parent;
            }
        }

        LOG.warning("No issuer in the TrustedList for this certificate. The parent found is " + parent);
        return null;
    }

    /**
     * Return the ServiceInfo of the parent (in the Trusted List) of the certificate
     * 
     * @return
     */
    public ServiceInfo getRelevantServiceInfo() {

        CertificateAndContext cert = new CertificateAndContext(getCertificate());
        CertificateAndContext parent = getParentFromTrustedList(cert);

        if (parent == null) {
            return null;
        } else {
            ServiceInfo info = (ServiceInfo) parent.getContext();
            return info;
        }

    }

    /**
     * Return the qualifications statement for the signing certificate
     * 
     * @return
     */
    public List<String> getQualificationStatement() {
        ServiceInfo info = getRelevantServiceInfo();
        LOG.info("Service Information " + info);
        if (info == null) {
            return null;
        } else {
            return info.getQualifiers(new CertificateAndContext(getCertificate()));
        }
    }

    /**
     * 
     * @param listener
     */
    public void addListener(SignatureEventListener listener) {
        signatureEventDelegate.addListener(listener);
    }

    /**
     * 
     * @param listener
     */
    public void removeListener(SignatureEventListener listener) {
        signatureEventDelegate.removeListener(listener);
    }

}
