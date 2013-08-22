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

import eu.europa.ec.markt.dss.NotETSICompliantException;
import eu.europa.ec.markt.dss.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.pdf.ITextPDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelA;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelLTV;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelXL;
import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;

/**
 * Validation of PDF document.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PDFDocumentValidator extends SignedDocumentValidator {

    private static final Logger LOG = Logger.getLogger(PDFDocumentValidator.class.getName());

    PDFSignatureService pdfSignatureService;

    /**
     * The default constructor for PDFDocumentValidator.
     */
    public PDFDocumentValidator(Document document) {
        this.document = document;
        pdfSignatureService = new ITextPDFSignatureService();
    }

    @Override
    public List<AdvancedSignature> getSignatures() {
        final List<AdvancedSignature> list = new ArrayList<AdvancedSignature>();

        try {
            PDFSignatureService pdfSignatureService = new ITextPDFSignatureService();
            pdfSignatureService.validateSignatures(this.document.openStream(), new SignatureValidationCallback() {

                @Override
                public void validate(PdfReader reader, PdfDictionary outerCatalog, X509Certificate arg0, Date arg1,
                        Certificate[] arg2, PdfDictionary signatureDictionary, PdfPKCS7 pk) {

                    if (arg0 == null) {
                        throw new NotETSICompliantException(MSG.NO_SIGNING_CERTIFICATE);
                    }

                    if (arg1 == null) {
                        // throw new NotETSICompliantException(MSG.NO_SIGNING_TIME);
                    }

                    try {
                        if (!signatureDictionary.get(new PdfName("Type")).equals(new PdfName("DocTimeStamp"))) {
                            list.add(new PAdESSignature(reader, outerCatalog, signatureDictionary, pk));
                        }
                    } catch (CMSException ex) {
                        throw new RuntimeException(ex);
                    }
                }
            });
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return list;
    }

    @Override
    protected SignatureLevelBES verifyLevelBES(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
        SignatureLevelBES superchecks = super.verifyLevelBES(signature, referenceTime, ctx);
        PAdESSignature pades = (PAdESSignature) signature;

        PdfName subfilter = pades.getSignatureDictionary().getAsName(PdfName.SUBFILTER);

        if (subfilter == null
                || (!subfilter.equals(new PdfName("ETSI.CAdES.detached")) && !subfilter.equals(new PdfName(
                        "ETSI.RFC3161")))) {
            LOG.warning("Invalid or missing SubFilter value in the signature dictionary; should be either ETSI.CAdES.detached or ETSI.RFC3161");
        }

        return superchecks;
    }

    @Override
    protected SignatureLevelC verifyLevelC(AdvancedSignature signature, Date referenceTime, ValidationContext ctx,
            boolean rehash) {
        /* There is no level C in PAdES signature. Return null */
        return null;
    }

    @Override
    protected SignatureLevelX verifyLevelX(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
        /* There is no level X in PAdES signature. Return null */
        return null;
    }

    @Override
    protected SignatureLevelXL verifyLevelXL(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
        /* There is no level XL in PAdES signature. Return null */
        return null;
    }

    @Override
    protected SignatureLevelA verifyLevelA(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
        /* There is no level A in PAdES signature. Return null */
        return null;
    }

    private boolean checkVriDict(PdfDictionary vriSigDictionary, boolean _vriVerificationresult,
            PAdESSignature pades, ValidationContext ctx, String hexHash) throws CertificateException, IOException,
            CRLException, OCSPException {

        boolean vriVerificationresult = _vriVerificationresult;

        if (vriSigDictionary == null) {
            LOG.info("Couldn't find the signature VRI identified by " + hexHash + " in the DSS");
            vriVerificationresult = false;
        } else {
            LOG.info("Found the signature VRI identified by " + hexHash + " in the DSS");

            // Verify the certs in the VRI
            PdfArray vricert = vriSigDictionary.getAsArray(new PdfName("Cert"));
            if (vricert != null) {
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                List<X509Certificate> certs = new ArrayList<X509Certificate>();
                for (int i = 0; i < vricert.size(); i++) {
                    PdfStream stream = vricert.getAsStream(i);
                    certs.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(PdfReader
                            .getStreamBytes((PRStream) stream))));
                }
                vriVerificationresult &= everyCertificateValueAreThere(ctx, certs, pades.getSigningCertificate());
            }

            // Verify the CRLs in the VRI
            PdfArray vricrl = vriSigDictionary.getAsArray(new PdfName("CRL"));
            if (vricrl != null) {
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                List<X509CRL> crls = new ArrayList<X509CRL>();
                for (int i = 0; i < vricrl.size(); i++) {
                    PdfStream stream = vricrl.getAsStream(i);
                    crls.add((X509CRL) factory.generateCRL(new ByteArrayInputStream(PdfReader
                            .getStreamBytes((PRStream) stream))));
                }
                vriVerificationresult &= everyCRLValueOrRefAreThere(ctx, crls);
            }

            // Verify the OCSPs in the VRI
            PdfArray vriocsp = vriSigDictionary.getAsArray(new PdfName("OCSP"));
            if (vriocsp != null) {
                List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
                for (int i = 0; i < vriocsp.size(); i++) {
                    PdfStream stream = vriocsp.getAsStream(i);
                    ocsps.add((BasicOCSPResp) new OCSPResp(PdfReader.getStreamBytes((PRStream) stream))
                            .getResponseObject());
                }
                vriVerificationresult &= everyOCSPValueOrRefAreThere(ctx, ocsps);
            }

        }

        return vriVerificationresult;
    }

    @Override
    protected SignatureLevelLTV verifyLevelLTV(AdvancedSignature signature, Date referenceTime, ValidationContext ctx) {
        try {
            PAdESSignature pades = (PAdESSignature) signature;
            LOG.info("Starting LTV validation of signature: " + pades.getPdfPkcs7().getSignName() + " / "
                    + PdfPKCS7.getSubjectFields(pades.getPdfPkcs7().getSigningCertificate()));

            PdfDictionary catalog = pades.getOuterCatalog();
            if (catalog == null) {
                catalog = pades.getPdfReader().getCatalog();
            }

            PdfDictionary dss = catalog.getAsDict(new PdfName("DSS"));

            if (dss == null) {
                LOG.info("No DSS dictionary!");
                return new SignatureLevelLTV(new Result(ResultStatus.INVALID, "no.dss.dictionary"), null, null);
            }

            LOG.info("DSS dictionary found");

            PdfName sigType = pades.getSignatureDictionary().getAsName(PdfName.TYPE);
            // PdfName subfilter = pades.getSignatureDictionary().getAsName(PdfName.SUBFILTER);

            TimestampVerificationResult docTimestampCheck = null;

            boolean dssCertsVerificationResult = everyCertificateValueAreThere(ctx, pades
                    .getExtendedCertificateSource().getCertificates(), pades.getSigningCertificate());
            boolean dssRevocationVerificationResult = true;
            dssRevocationVerificationResult &= everyCRLValueOrRefAreThere(ctx, pades.getCRLs());
            dssRevocationVerificationResult &= everyOCSPValueOrRefAreThere(ctx, pades.getOCSPs());
            boolean vriVerificationresult = true;

            if (sigType != null) {
                if (sigType.equals(new PdfName("Sig"))) {
                    // Standard signature

                    PdfDictionary vri = dss.getAsDict(new PdfName("VRI"));

                    if (vri == null) {
                        LOG.info("No VRI dictionary, this is optional but required by Adobe Acrobat");
                        return new SignatureLevelLTV(new Result(ResultStatus.INVALID, "no.vri.dictionary"), null,
                                null);
                    }

                    // Verify the VRI
                    MessageDigest _md = MessageDigest.getInstance("SHA1");
                    String hexHash = Hex.encodeHexString(
                            _md.digest(pades.getSignatureDictionary().get(PdfName.CONTENTS).getBytes()))
                            .toUpperCase();

                } else if (sigType.equals(new PdfName("DocTimeStamp"))) {

                } else {
                    throw new RuntimeException("Unknown signature dictionary type");
                }
            }

            Result levelReached = null;
            if (dssCertsVerificationResult && dssRevocationVerificationResult) {
                levelReached = new Result(ResultStatus.VALID, null);
            } else {
                levelReached = new Result();
                if (!dssCertsVerificationResult) {
                    levelReached.setStatus(ResultStatus.INVALID, "dss.certs.verification.result.error");
                } else if (!dssRevocationVerificationResult) {
                    levelReached.setStatus(ResultStatus.INVALID, "dss.revocation.verification.result.error");
                } else if (!vriVerificationresult) {
                    levelReached.setStatus(ResultStatus.INVALID, "vri.verification.result.error");
                }
            }

            return new SignatureLevelLTV(levelReached, new Result((dssCertsVerificationResult) ? ResultStatus.VALID
                    : ResultStatus.INVALID, null), new Result((dssRevocationVerificationResult) ? ResultStatus.VALID
                    : ResultStatus.INVALID, null));

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
