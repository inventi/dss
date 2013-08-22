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

package eu.europa.ec.markt.dss.signature.xades;

import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.io.IOUtils;

/**
 * XAdES implementation of DocumentSignatureService
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESService implements DocumentSignatureService {

    private TSPSource tspSource;

    private CertificateVerifier certificateVerifier;

    /**
     * @param certificateVerifier the certificateVerifier to set
     */
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * @param tspSource the tspSource to set
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    private XAdESProfileBES getSigningProfile(SignatureParameters parameters) {
        switch (parameters.getSignatureFormat()) {
        case XAdES_BES:
            return new XAdESProfileBES();
        case XAdES_EPES:
        default:
            return new XAdESProfileEPES();
        }
    }

    private SignatureExtension getExtensionProfile(SignatureParameters parameters) {
        switch (parameters.getSignatureFormat()) {
        case XAdES_BES:
        case XAdES_EPES:
            return null;
        case XAdES_T:
            XAdESProfileT extensionT = new XAdESProfileT();
            extensionT.setTspSource(tspSource);
            return extensionT;
        case XAdES_C:
            XAdESProfileC extensionC = new XAdESProfileC();
            extensionC.setTspSource(tspSource);
            extensionC.setCertificateVerifier(certificateVerifier);
            return extensionC;
        case XAdES_X:
            XAdESProfileX extensionX = new XAdESProfileX();
            extensionX.setTspSource(tspSource);
            extensionX.setCertificateVerifier(certificateVerifier);
            return extensionX;
        case XAdES_XL:
            XAdESProfileXL extensionXL = new XAdESProfileXL();
            extensionXL.setTspSource(tspSource);
            extensionXL.setCertificateVerifier(certificateVerifier);
            return extensionXL;
        case XAdES_A:
            XAdESProfileA extensionA = new XAdESProfileA();
            extensionA.setTspSource(tspSource);
            extensionA.setCertificateVerifier(certificateVerifier);
            return extensionA;
        default:
            throw new RuntimeException("Unsupported signature format " + parameters.getSignatureFormat());
        }
    }

    @Override
    public Digest digest(Document document, SignatureParameters parameters) throws IOException {
        try {
            InputStream input = toBeSigned(document, parameters);
            byte[] data = IOUtils.toByteArray(input);
            MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
            
            byte[] digestValue = digest.digest(data);
            return new Digest(DigestAlgorithm.SHA1, digestValue);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream toBeSigned(Document document, SignatureParameters parameters) throws IOException {
        return getSigningProfile(parameters).getToBeSignedStream(document, parameters);
    }

    @Override
    public Document signDocument(Document document, SignatureParameters parameters, byte[] signatureValue)
            throws IOException {
        XAdESProfileBES profile = getSigningProfile(parameters);

        Document signedDoc = profile.signDocument(document, parameters, signatureValue);

        SignatureExtension extension = getExtensionProfile(parameters);
        if (extension != null) {
            if (parameters.getSignaturePackaging() == SignaturePackaging.ENVELOPED) {
                String signatureId = "sigId-" + profile.computeDeterministicId(parameters);
                return extension.extendSignature(signatureId, signedDoc, document, parameters);
            } else {
                return extension.extendSignatures(signedDoc, document, parameters);
            }
        } else {
            return signedDoc;
        }
    }

    @Override
    public Document extendDocument(Document document, Document originalDocument, SignatureParameters parameters)
            throws IOException {
        SignatureExtension extension = getExtensionProfile(parameters);
        if (extension != null) {
            return extension.extendSignatures(document, originalDocument, parameters);
        } else {
            return document;
        }
    }

}
