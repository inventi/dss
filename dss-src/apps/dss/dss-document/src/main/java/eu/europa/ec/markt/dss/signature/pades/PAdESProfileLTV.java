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

package eu.europa.ec.markt.dss.signature.pades;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.NotETSICompliantException;
import eu.europa.ec.markt.dss.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.pdf.ITextPDFDocTimeSampService;
import eu.europa.ec.markt.dss.signature.pdf.ITextPDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampResponse;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDeveloperExtension;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfStream;

/**
 * Extend a PAdES extension up to LTV.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PAdESProfileLTV implements SignatureExtension {

    private PDFSignatureService pdfSignatureService = new ITextPDFSignatureService();

    private CertificateVerifier certificateVerifier;

    private Map<X509Certificate, PdfIndirectReference> certsRefs = new HashMap<X509Certificate, PdfIndirectReference>();
    private Map<X509CRL, PdfIndirectReference> crlRefs = new HashMap<X509CRL, PdfIndirectReference>();
    private Map<BasicOCSPResp, PdfIndirectReference> ocspRefs = new HashMap<BasicOCSPResp, PdfIndirectReference>();

    private TSPSource tspSource;

    /**
     * @param tspSource the tspSource to set
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * @param certificateVerifier the certificateVerifier to set
     */
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    class LTVSignatureValidationCallback implements SignatureValidationCallback {

        private PdfStamper stamper;

        private PdfArray certsArray = new PdfArray();

        private PdfArray ocspsArray = new PdfArray();

        private PdfArray crlsArray = new PdfArray();

        private ValidationContext validationContext;

        private byte[] signatureBlock;

        public LTVSignatureValidationCallback(PdfStamper stamper) {
            this.stamper = stamper;
        }

        @Override
        public void validate(PdfReader reader, PdfDictionary outerCatalog, X509Certificate signingCert,
                Date signingDate, Certificate[] certs, PdfDictionary signatureDictionary, PdfPKCS7 pk) {

            if (signingCert == null) {
                throw new NotETSICompliantException(MSG.NO_SIGNING_CERTIFICATE);
            }

            if (signingDate == null) {
                throw new NotETSICompliantException(MSG.NO_SIGNING_TIME);
            }

            try {

                this.signatureBlock = signatureDictionary.get(PdfName.CONTENTS).getBytes();

                CAdESSignature cades = new CAdESSignature(signatureBlock);
                final ValidationContext ctx = certificateVerifier.validateCertificate(signingCert, signingDate,
                        cades.getCertificateSource(), null, null);
                if (cades.getSignatureTimestamps() != null) {
                    for (TimestampToken tstoken : cades.getSignatureTimestamps()) {
                        ctx.validateTimestamp(tstoken, cades.getCertificateSource(), null, null);
                    }
                }

                for (BasicOCSPResp ocsp : ctx.getNeededOCSPResp()) {
                    try {
                        PdfIndirectReference cRef = stamper.getWriter().getPdfIndirectReference();
                        PdfStream stream = new PdfStream(OCSPUtils.fromBasicToResp(ocsp).getEncoded());
                        stamper.getWriter().addToBody(stream, cRef, false);
                        ocspsArray.add(cRef);
                        ocspRefs.put(ocsp, cRef);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }

                for (X509CRL crl : ctx.getNeededCRL()) {
                    try {
                        PdfIndirectReference cRef = stamper.getWriter().getPdfIndirectReference();
                        PdfStream stream = new PdfStream(crl.getEncoded());
                        stamper.getWriter().addToBody(stream, cRef, false);
                        crlsArray.add(cRef);
                        crlRefs.put(crl, cRef);
                    } catch (CRLException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }

                for (CertificateAndContext cert : ctx.getNeededCertificates()) {
                    try {
                        PdfIndirectReference cRef = stamper.getWriter().getPdfIndirectReference();
                        PdfStream stream = new PdfStream(cert.getCertificate().getEncoded());
                        stamper.getWriter().addToBody(stream, cRef, false);
                        certsArray.add(cRef);
                        certsRefs.put(cert.getCertificate(), cRef);
                    } catch (CertificateEncodingException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            } catch (CMSException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * @return the certsArray
         */
        public PdfArray getCertsArray() {
            return certsArray;
        }

        /**
         * @return the crlsArray
         */
        public PdfArray getCrlsArray() {
            return crlsArray;
        }

        /**
         * @return the ocspsArray
         */
        public PdfArray getOcspsArray() {
            return ocspsArray;
        }

        /**
         * @return the signatureBlock
         */
        public byte[] getSignatureBlock() {
            return signatureBlock;
        }

        /**
         * @return the validationContext
         */
        public ValidationContext getValidationContext() {
            return validationContext;
        }

    }

    private PdfIndirectReference buildVRIDict(PdfStamper stamper, BasicOCSPResp crl) throws IOException {
        PdfIndirectReference ref = stamper.getWriter().getPdfIndirectReference();
        PdfDictionary ocspVriDictionary = new PdfDictionary();
        PdfDate vriDate = new PdfDate(Calendar.getInstance(TimeZone.getTimeZone("GMT")));
        ocspVriDictionary.put(new PdfName("TU"), vriDate);

        // Other objects?

        stamper.getWriter().addToBody(ocspVriDictionary, ref, false);
        return ref;
    }

    private PdfIndirectReference buildVRIDict(PdfStamper stamper, X509CRL crl) throws IOException {
        PdfIndirectReference ref = stamper.getWriter().getPdfIndirectReference();
        PdfDictionary crlVriDictionary = new PdfDictionary();
        PdfDate vriDate = new PdfDate(Calendar.getInstance(TimeZone.getTimeZone("GMT")));
        crlVriDictionary.put(new PdfName("TU"), vriDate);

        // Other objects?

        stamper.getWriter().addToBody(crlVriDictionary, ref, false);
        return ref;
    }

    private void integrateCRL(LTVSignatureValidationCallback callback, PdfStamper stamper,
            PdfDictionary dssDictionary, PdfDictionary sigVriDictionary, PdfDictionary vriDictionary)
            throws IOException {
        if (callback.getCrlsArray().size() > 0) {
            // Reference in the DSS dictionary
            PdfIndirectReference crlsRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(callback.getCrlsArray(), crlsRef, false);
            dssDictionary.put(new PdfName("CRLs"), crlsRef);

            // Array in the signature's VRI dictionary
            PdfIndirectReference sigVriCrlRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(callback.getCrlsArray(), sigVriCrlRef, false);
            sigVriDictionary.put(new PdfName("CRL"), sigVriCrlRef);

            // Build and reference a VRI dictionary for each CRL
            for (X509CRL crl : crlRefs.keySet()) {
                try {
                    PdfIndirectReference vriRef = buildVRIDict(stamper, crl);
                    MessageDigest md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
                    String hexHash = Hex.encodeHexString(md.digest(crl.getSignature())).toUpperCase();
                    vriDictionary.put(new PdfName(hexHash), vriRef);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException();
                }
            }
        }
    }

    private void integrateOCSP(LTVSignatureValidationCallback callback, PdfStamper stamper,
            PdfDictionary dssDictionary, PdfDictionary sigVriDictionary, PdfDictionary vriDictionary)
            throws IOException {
        if (callback.getOcspsArray().size() > 0) {
            // Reference in the DSS dictionary
            PdfIndirectReference ocspsRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(callback.getOcspsArray(), ocspsRef, false);
            dssDictionary.put(new PdfName("OCSPs"), ocspsRef);

            // Array in the signature's VRI dictionary
            PdfIndirectReference sigVriOcspRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(callback.getOcspsArray(), sigVriOcspRef, false);
            sigVriDictionary.put(new PdfName("OCSP"), sigVriOcspRef);

            // Build and reference a VRI dictionary for each OCSP response
            for (BasicOCSPResp ocsp : ocspRefs.keySet()) {
                try {
                    PdfIndirectReference vriRef = buildVRIDict(stamper, ocsp);
                    MessageDigest md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
                    String hexHash = Hex.encodeHexString(md.digest(ocsp.getSignature())).toUpperCase();
                    vriDictionary.put(new PdfName(hexHash), vriRef);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException();
                }
            }
        }
    }

    @Override
    public Document extendSignatures(Document document, Document originalData, SignatureParameters parameters)
            throws IOException {

        try {
            final PdfReader reader = new PdfReader(document.openStream());
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final PdfStamper stamper = new PdfStamper(reader, output, '\0', true);

            LTVSignatureValidationCallback callback = new LTVSignatureValidationCallback(stamper);
            pdfSignatureService.validateSignatures(document.openStream(), callback);

            PdfIndirectReference certsRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(callback.getCertsArray(), certsRef, false);

            PdfDictionary dssDictionary = new PdfDictionary(new PdfName("DSS"));
            PdfDictionary vriDictionary = new PdfDictionary(new PdfName("VRI"));

            PdfDictionary sigVriDictionary = new PdfDictionary();

            integrateCRL(callback, stamper, dssDictionary, sigVriDictionary, sigVriDictionary);

            integrateOCSP(callback, stamper, dssDictionary, sigVriDictionary, sigVriDictionary);

            // Add the signature's VRI dictionary, hashing the signature block from the callback method
            MessageDigest _md = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
            String hexHash = Hex.encodeHexString(_md.digest(callback.getSignatureBlock())).toUpperCase();

            PdfIndirectReference sigVriRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(sigVriDictionary, sigVriRef, false);
            vriDictionary.put(new PdfName(hexHash), sigVriRef);
            PdfIndirectReference vriRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(vriDictionary, vriRef, false);

            // Add final objects to DSS dictionary
            dssDictionary.put(new PdfName("VRI"), vriRef);
            dssDictionary.put(new PdfName("Certs"), certsRef);

            PdfIndirectReference dssRef = stamper.getWriter().getPdfIndirectReference();
            stamper.getWriter().addToBody(dssDictionary, dssRef, false);
            reader.getCatalog().put(new PdfName("DSS"), dssRef);

            // /Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 5>>>>
            PdfDeveloperExtension etsiExtension = new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 5);
            stamper.getWriter().addDeveloperExtension(etsiExtension);
            stamper.getWriter().addToBody(reader.getCatalog(), reader.getCatalog().getIndRef(), false);

            stamper.close();
            output.close();

            Document extendedDocument = new InMemoryDocument(output.toByteArray());

            ByteArrayOutputStream ltvDoc = new ByteArrayOutputStream();

            ITextPDFDocTimeSampService service = new ITextPDFDocTimeSampService();
            byte[] digest = service.digest(extendedDocument.openStream(), parameters);
            TimeStampResponse tsToken = tspSource.getTimeStampResponse(parameters.getDigestAlgorithm(), digest);
            service.sign(extendedDocument.openStream(), tsToken.getTimeStampToken().getEncoded(), ltvDoc, parameters);

            return new InMemoryDocument(ltvDoc.toByteArray());

        } catch (DocumentException ex) {
            throw new RuntimeException(ex);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public Document extendSignature(Object signatureId, Document document, Document originalData,
            SignatureParameters parameters) throws IOException {
        /* On PAdES, we retrieve the data for all the signatures */
        return extendSignatures(document, originalData, parameters);
    }

}
