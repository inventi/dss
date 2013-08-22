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

package eu.europa.ec.markt.dss.validation.pades;

import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureFormat;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CompositeCertificateSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import java.security.SignatureException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;

import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

/**
 * Implementation of AdvancedSignature for PAdES
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(PAdESSignature.class.getName());

    private PdfReader pdfReader;
    private PdfDictionary outerCatalog;
    private PdfDictionary signatureDictionary;

    private CAdESSignature cadesSignature;

    private PdfPKCS7 pk;

    /**
     * 
     * The default constructor for PAdESSignature.
     * 
     * @param reader The PdfReader that enable to access the document that contains the PAdES signature.
     */
    public PAdESSignature(PdfReader reader, PdfDictionary outerCatalog, PdfDictionary signatureDictionary,
            PdfPKCS7 pk) throws CMSException {
        this.pdfReader = reader;
        this.outerCatalog = outerCatalog;
        this.signatureDictionary = signatureDictionary;
        cadesSignature = new CAdESSignature(signatureDictionary.get(PdfName.CONTENTS).getBytes());
        this.pk = pk;
    }

    @Override
    public SignatureFormat getSignatureFormat() {
        return SignatureFormat.PAdES;
    }

    @Override
    public String getSignatureAlgorithm() {
        if (cadesSignature == null) {
            return null;
        }
        return cadesSignature.getSignatureAlgorithm();
    }

    @Override
    public CertificateSource getCertificateSource() {
        return new CompositeCertificateSource(cadesSignature.getCertificateSource(),
                (outerCatalog != null) ? new PAdESCertificateSource(outerCatalog) : new PAdESCertificateSource(
                        pdfReader));
    }

    @Override
    public PAdESCertificateSource getExtendedCertificateSource() {
        return (outerCatalog != null) ? new PAdESCertificateSource(outerCatalog) : new PAdESCertificateSource(
                pdfReader);
    }

    @Override
    public PAdESCRLSource getCRLSource() {
        return (outerCatalog != null) ? new PAdESCRLSource(outerCatalog) : new PAdESCRLSource(pdfReader);
    }

    @Override
    public PAdESOCSPSource getOCSPSource() {
        return (outerCatalog != null) ? new PAdESOCSPSource(outerCatalog) : new PAdESOCSPSource(pdfReader);
    }

    @Override
    public X509Certificate getSigningCertificate() {
        return cadesSignature.getSigningCertificate();
    }

    @Override
    public Date getSigningTime() {
        Date date = null;
        if (pk.getSignDate() != null) {
            date = pk.getSignDate().getTime();
        }
        if (date == null) {
            return cadesSignature.getSigningTime();
        } else {
            return date;
        }
    }

    @Override
    public PolicyValue getPolicyId() {
        return cadesSignature.getPolicyId();
    }

    @Override
    public String getLocation() {
        String location = pk.getLocation();
        if (location == null || location.trim().length() == 0) {
            return cadesSignature.getLocation();
        } else {
            return location;
        }
    }

    @Override
    public String getContentType() {
        return "application/pdf";
    }

    @Override
    public String[] getClaimedSignerRoles() {
        return cadesSignature.getClaimedSignerRoles();
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() {
        return cadesSignature.getSignatureTimestamps();
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<X509Certificate> getCertificates() {
        return cadesSignature.getCertificates();
    }

    @Override
    public boolean checkIntegrity(Document document) {
        try {
            if (signatureDictionary.get(PdfName.SUBFILTER) != null
                    && new PdfName("ETSI.RFC3161").equals(signatureDictionary.get(PdfName.SUBFILTER))) {
                return pk.verify();
            } else {
                return pk.verify();
            }
        } catch (SignatureException e) {
            LOG.log(Level.WARNING, "Coulnd not check integrity", e);
            return false;
        }
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<CertificateRef> getCertificateRefs() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<CRLRef> getCRLRefs() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<OCSPRef> getOCSPRefs() {
        /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<X509CRL> getCRLs() {
        return getCRLSource().getCRLsFromSignature();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {
        return getOCSPSource().getOCSPResponsesFromSignature();
    }

    @Override
    public byte[] getSignatureTimestampData() {
        return cadesSignature.getSignatureTimestampData();
    }

    @Override
    public byte[] getTimestampX1Data() {
        /* Not applicable for PAdES */
        return null;
    }

    @Override
    public byte[] getTimestampX2Data() {
        /* Not applicable for PAdES */
        return null;
    }

    @Override
    public byte[] getArchiveTimestampData(int index, Document originalData) {
        /* Not applicable for PAdES */
        return null;
    }

    /**
     * @return the PKCS7 object corresponding to the signature
     */
    public PdfPKCS7 getPdfPkcs7() {
        return pk;
    }

    /**
     * @return the pdfReader corresponding to the revision of the document covered by the signature
     */
    public PdfReader getPdfReader() {
        return pdfReader;
    }

    /**
     * @return the CAdES signature underlying this PAdES signature
     */
    public CAdESSignature getCAdESSignature() {
        return cadesSignature;
    }

    /**
     * @return the "outer" catalog outside the document covered by this signature
     */
    public PdfDictionary getOuterCatalog() {
        return outerCatalog;
    }

    /**
     * @return the signature dictionary containing the bytes
     */
    public PdfDictionary getSignatureDictionary() {
        return signatureDictionary;
    }

}
