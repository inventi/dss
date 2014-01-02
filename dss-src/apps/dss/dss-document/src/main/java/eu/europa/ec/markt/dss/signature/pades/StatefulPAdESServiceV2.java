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

import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.cades.CAdESProfileT;
import eu.europa.ec.markt.dss.signature.cades.PreComputedContentSigner;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.StatefulITextPDFSignatureService;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import com.lowagie.text.DocumentException;

/**
 * PAdES implementation of the DocumentSignatureService
 *
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class StatefulPAdESServiceV2 implements DocumentSignatureService {

    private static final Logger LOG = Logger.getLogger(StatefulPAdESServiceV2.class.getName());

    private TSPSource tspSource;

    private CertificateVerifier certificateVerifier;

    private StatefulITextPDFSignatureService pdfService;

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

    private PAdESProfileLTV getExtensionProfile(SignatureParameters parameters) {
        switch (parameters.getSignatureFormat()) {
            case PAdES_BES:
            case PAdES_EPES:
                return null;
            case PAdES_LTV:
                PAdESProfileLTV profile = new PAdESProfileLTV();
                profile.setCertificateVerifier(certificateVerifier);
                profile.setTspSource(tspSource);
                return profile;
            default:
                throw new IllegalArgumentException("Signature format '" + parameters.getSignatureFormat()
                        + "' not supported");
        }
    }

    private StatefulITextPDFSignatureService getPDFService(){
        if(pdfService == null){
            pdfService = new StatefulITextPDFSignatureService();
        }
        return pdfService;
    }

    @Override
    public InputStream toBeSigned(Document document, SignatureParameters parameters) throws IOException {
        try {
            PAdESProfileEPES padesProfile = new PAdESProfileEPES();

            PDFSignatureService pdfSignatureService = getPDFService();
            byte[] messageDigest = pdfSignatureService.digest(document.openStream(), parameters);

            LOG.fine("Calculated digest on byterange " + Hex.encodeHexString(messageDigest));

            PreComputedContentSigner contentSigner = new PreComputedContentSigner(
                    SignatureAlgorithm.RSA.getJavaSignatureAlgorithm(parameters.getDigestAlgorithm()));

            DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
            CMSSignedDataGenerator generator = padesProfile.createCMSSignedDataGenerator(contentSigner,
                    digestCalculatorProvider, parameters, messageDigest);

            CMSProcessableByteArray content = new CMSProcessableByteArray(pdfSignatureService.digest(
                    document.openStream(), parameters));

            generator.generate(content, false);

            return new ByteArrayInputStream(contentSigner.getByteOutputStream().toByteArray());
        } catch (CMSException e) {
            throw new IOException(e);
        } catch (DocumentException e) {
            throw new IOException(e);
        }

    }

    @Override
    public Digest digest(Document document, SignatureParameters parameters) throws IOException {
        byte[] digestValue = null;
        MessageDigest dig;
        try {
            dig = MessageDigest.getInstance(parameters.getDigestAlgorithm().getName());
            digestValue = dig.digest(IOUtils.toByteArray(toBeSigned(document, parameters)));
            return new Digest(parameters.getDigestAlgorithm(), digestValue);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No " + parameters.getDigestAlgorithm() + " algorithm available ?!");
        }
    }

    @Override
    public Document signDocument(Document document, SignatureParameters parameters, byte[] signatureValue)
            throws IOException {
        try {

            PAdESProfileEPES padesProfile = new PAdESProfileEPES();

            PreComputedContentSigner contentSigner = new PreComputedContentSigner(
                    SignatureAlgorithm.RSA.getJavaSignatureAlgorithm(parameters.getDigestAlgorithm()),
                    signatureValue);
            DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

            PDFSignatureService pdfSignatureService = getPDFService();
            byte[] messageDigest = pdfSignatureService.digest(document.openStream(), parameters);

            CMSSignedDataGenerator generator = padesProfile.createCMSSignedDataGenerator(contentSigner,
                    digestCalculatorProvider, parameters, messageDigest);

            CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

            CMSSignedData data = generator.generate(content, false);
            if (tspSource != null) {
                CAdESProfileT t = new CAdESProfileT();
                t.setSignatureTsa(tspSource);
                data = t.extendCMSSignedData(data, null, parameters);
            }

            ByteArrayOutputStream output = new ByteArrayOutputStream();

            pdfSignatureService.sign(document.openStream(), data.getEncoded(), output, parameters);
            output.close();

            Document doc = new InMemoryDocument(output.toByteArray());

            PAdESProfileLTV extension = getExtensionProfile(parameters);
            if (extension != null) {
                return extension.extendSignatures(doc, null, parameters);
            } else {
                return doc;
            }

        } catch (DocumentException ex) {
            throw new IOException(ex);
        } catch (CMSException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Document extendDocument(Document document, Document originalDocument, SignatureParameters parameters)
            throws IOException {
        PAdESProfileLTV extension = getExtensionProfile(parameters);
        if (extension != null) {
            return extension.extendSignatures(document, originalDocument, parameters);
        } else {
            return document;
        }
    }
}
