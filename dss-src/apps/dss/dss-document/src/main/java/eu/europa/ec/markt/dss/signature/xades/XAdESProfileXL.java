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

import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;
import eu.europa.ec.markt.dss.validation.xades.XAdESCertificateSource;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertificateValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.EncapsulatedPKIDataType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.RevocationValuesType;
import eu.europa.ec.markt.tsl.jaxb.xades.UnsignedPropertiesType;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.Init;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.w3c.dom.Element;

/**
 * XL profile of XAdES signature
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESProfileXL extends XAdESProfileX {

    private static final Logger LOG = Logger.getLogger(XAdESProfileXL.class.getName());

    /**
     * The default constructor for XAdESProfileT.
     * 
     */
    public XAdESProfileXL() {
        super();
        Init.init();
    }

    private void extendSignatureTag(Element signatureEl, UnsignedPropertiesType unsigned,
            SignatureFormat signatureFormat) throws IOException {

        try {

            XAdESSignature signature = new XAdESSignature(signatureEl);
            X509Certificate signingCertificate = signature.getSigningCertificate();
            Date signingTime = signature.getSigningTime();

            List<Object> toRemove = new ArrayList<Object>();
            if (unsigned.getUnsignedSignatureProperties() != null
                    && unsigned.getUnsignedSignatureProperties()
                            .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs() != null) {
                Iterator<?> it = unsigned.getUnsignedSignatureProperties()
                        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().iterator();
                while (it.hasNext()) {
                    Object e = it.next();
                    if (e instanceof RevocationValuesType || e instanceof CertificateValuesType) {
                        toRemove.add(e);
                    } else if (e instanceof JAXBElement) {
                        e = ((JAXBElement<?>) e).getValue();
                        if (e instanceof RevocationValuesType || e instanceof CertificateValuesType) {
                            toRemove.add(e);
                        }
                    }
                }
            }

            if (toRemove.size() == 0 || signatureFormat == SignatureFormat.XAdES_XL
                    || signatureFormat == SignatureFormat.XAdES_A) {

                LOG.info("Validation for XAdES-XL");
                ValidationContext ctx = certificateVerifier.validateCertificate(signingCertificate, signingTime,
                        new XAdESCertificateSource(signatureEl, false), null, null);

                CertificateValuesType certificateValues = xadesObjectFactory.createCertificateValuesType();
                List<Serializable> certificateValuesList = certificateValues
                        .getEncapsulatedX509CertificateOrOtherCertificate();

                for (CertificateAndContext certificate : ctx.getNeededCertificates()) {
                    LOG.info("Add certificate value for " + certificate);
                    EncapsulatedPKIDataType encapsulatedPKIDataType = xadesObjectFactory
                            .createEncapsulatedPKIDataType();
                    try {
                        encapsulatedPKIDataType.setValue(certificate.getCertificate().getEncoded());
                    } catch (CertificateEncodingException e) {
                        throw new RuntimeException("certificate encoding error: " + e.getMessage(), e);
                    }
                    certificateValuesList.add(encapsulatedPKIDataType);
                }

                RevocationValuesType revocationValues = xadesObjectFactory.createRevocationValuesType();
                if (!ctx.getNeededCRL().isEmpty()) {
                    CRLValuesType crlValues = xadesObjectFactory.createCRLValuesType();
                    revocationValues.setCRLValues(crlValues);
                    List<EncapsulatedPKIDataType> encapsulatedCrlValues = crlValues.getEncapsulatedCRLValue();

                    for (X509CRL crl : ctx.getNeededCRL()) {
                        EncapsulatedPKIDataType encapsulatedCrlValue = xadesObjectFactory
                                .createEncapsulatedPKIDataType();
                        encapsulatedCrlValue.setValue(crl.getEncoded());
                        encapsulatedCrlValues.add(encapsulatedCrlValue);
                    }

                }
                if (!ctx.getNeededOCSPResp().isEmpty()) {

                    OCSPValuesType ocspValues = xadesObjectFactory.createOCSPValuesType();
                    revocationValues.setOCSPValues(ocspValues);
                    List<EncapsulatedPKIDataType> encapsulatedOcspValues = ocspValues.getEncapsulatedOCSPValue();

                    for (BasicOCSPResp ocsp : ctx.getNeededOCSPResp()) {
                        EncapsulatedPKIDataType encapsulatedOcspValue = xadesObjectFactory
                                .createEncapsulatedPKIDataType();
                        encapsulatedOcspValue.setValue(OCSPUtils.fromBasicToResp(ocsp).getEncoded());
                        encapsulatedOcspValues.add(encapsulatedOcspValue);
                    }
                }

                for (Object o : toRemove) {
                    unsigned.getUnsignedSignatureProperties()
                            .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().remove(o);
                }

                unsigned.getUnsignedSignatureProperties()
                        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()
                        .add(xadesObjectFactory.createCertificateValues(certificateValues));
                unsigned.getUnsignedSignatureProperties()
                        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()
                        .add(xadesObjectFactory.createRevocationValues(revocationValues));

            }

        } catch (CRLException e) {
            throw new RuntimeException(e);
        }

    }

    protected void extendSignatureTag(Element signatureEl, Document originalData, SignatureFormat signatureFormat) {

        /* Go up to -X */
        super.extendSignatureTag(signatureEl, originalData, signatureFormat);

        try {

            Element qualifyingProperties = XMLUtils
                    .getElement(signatureEl, "./ds:Object/xades:QualifyingProperties");
            Element unsignedPropertiesNode = XMLUtils.getElement(qualifyingProperties, "./xades:UnsignedProperties");

            UnsignedPropertiesType unsignedPropertiesType = null;
            if (unsignedPropertiesNode != null) {
                unsignedPropertiesType = ((JAXBElement<UnsignedPropertiesType>) unmarshaller
                        .unmarshal(unsignedPropertiesNode)).getValue();
            } else {
                unsignedPropertiesType = xadesObjectFactory.createUnsignedPropertiesType();
            }

            extendSignatureTag(signatureEl, unsignedPropertiesType, signatureFormat);

            if (unsignedPropertiesNode != null) {
                qualifyingProperties.removeChild(unsignedPropertiesNode);
            }
            marshaller.marshal(xadesObjectFactory.createUnsignedProperties(unsignedPropertiesType),
                    qualifyingProperties);
        } catch (JAXBException e) {
            throw new RuntimeException("JAXB error: " + e.getMessage(), e);

        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
