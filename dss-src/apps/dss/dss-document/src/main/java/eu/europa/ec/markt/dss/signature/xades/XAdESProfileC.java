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

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPUtils;
import eu.europa.ec.markt.dss.validation.xades.XAdESCertificateSource;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLRefType;
import eu.europa.ec.markt.tsl.jaxb.xades.CRLRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDListType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDType;
import eu.europa.ec.markt.tsl.jaxb.xades.CompleteCertificateRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.CompleteRevocationRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.DigestAlgAndValueType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPRefType;
import eu.europa.ec.markt.tsl.jaxb.xades.OCSPRefsType;
import eu.europa.ec.markt.tsl.jaxb.xades.ResponderIDType;
import eu.europa.ec.markt.tsl.jaxb.xades.UnsignedPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.X509IssuerSerialType;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.Init;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.RespID;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Contains XAdES-C profile aspects
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESProfileC extends XAdESProfileT {

    private static final Logger LOG = Logger.getLogger(XAdESProfileC.class.getName());

    public static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

    public static final String XADES141_NAMESPACE = "http://uri.etsi.org/01903/v1.4.1#";

    protected CertificateVerifier certificateVerifier;

    private final DatatypeFactory datatypeFactory;

    /**
     * The default constructor for XAdESProfileT.
     * 
     * @throws DatatypeConfigurationException
     */
    public XAdESProfileC() {
        super();
        Init.init();

        try {
            datatypeFactory = DatatypeFactory.newInstance();
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * @param certificateVerifier the certificateVerifier to set
     */
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    private void incorporateCRLRefs(CompleteRevocationRefsType completeRevocationRefs, ValidationContext ctx) {
        if (!ctx.getNeededCRL().isEmpty()) {
            CRLRefsType crlRefs = xadesObjectFactory.createCRLRefsType();
            completeRevocationRefs.setCRLRefs(crlRefs);
            List<CRLRefType> crlRefList = crlRefs.getCRLRef();

            for (X509CRL crl : ctx.getNeededCRL()) {
                try {
                    CRLRefType crlRef = xadesObjectFactory.createCRLRefType();

                    CRLIdentifierType crlIdentifier = xadesObjectFactory.createCRLIdentifierType();
                    crlRef.setCRLIdentifier(crlIdentifier);
                    String issuerName = crl.getIssuerX500Principal().getName();
                    crlIdentifier.setIssuer(issuerName);

                    GregorianCalendar cal = (GregorianCalendar) GregorianCalendar.getInstance();
                    cal.setTime(crl.getThisUpdate());
                    crlIdentifier.setIssueTime(this.datatypeFactory.newXMLGregorianCalendar(cal));

                    // crlIdentifier.setNumber(getCrlNumber(encodedCrl));

                    DigestAlgAndValueType digestAlgAndValue = getDigestAlgAndValue(crl.getEncoded(),
                            DigestAlgorithm.SHA1);
                    crlRef.setDigestAlgAndValue(digestAlgAndValue);

                    crlRefList.add(crlRef);
                } catch (CRLException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
    }

    private void incorporateOCSPRefs(CompleteRevocationRefsType completeRevocationRefs, ValidationContext ctx) {
        if (!ctx.getNeededOCSPResp().isEmpty()) {
            OCSPRefsType ocspRefs = this.xadesObjectFactory.createOCSPRefsType();
            completeRevocationRefs.setOCSPRefs(ocspRefs);
            List<OCSPRefType> ocspRefList = ocspRefs.getOCSPRef();

            for (BasicOCSPResp basicOcspResp : ctx.getNeededOCSPResp()) {
                try {
                    OCSPRefType ocspRef = this.xadesObjectFactory.createOCSPRefType();

                    DigestAlgAndValueType digestAlgAndValue = getDigestAlgAndValue(
                            OCSPUtils.fromBasicToResp(basicOcspResp).getEncoded(), DigestAlgorithm.SHA1);
                    LOG.info("Add a reference for OCSP produced at " + basicOcspResp.getProducedAt() + " digest "
                            + Hex.encodeHexString(digestAlgAndValue.getDigestValue()));
                    ocspRef.setDigestAlgAndValue(digestAlgAndValue);

                    OCSPIdentifierType ocspIdentifier = xadesObjectFactory.createOCSPIdentifierType();
                    ocspRef.setOCSPIdentifier(ocspIdentifier);

                    Date producedAt = basicOcspResp.getProducedAt();

                    GregorianCalendar cal = (GregorianCalendar) GregorianCalendar.getInstance();
                    cal.setTime(producedAt);

                    ocspIdentifier.setProducedAt(this.datatypeFactory.newXMLGregorianCalendar(cal));

                    ResponderIDType responderId = this.xadesObjectFactory.createResponderIDType();
                    ocspIdentifier.setResponderID(responderId);
                    RespID respId = basicOcspResp.getResponderId();
                    ResponderID ocspResponderId = respId.toASN1Object();
                    DERTaggedObject derTaggedObject = (DERTaggedObject) ocspResponderId.toASN1Object();
                    if (2 == derTaggedObject.getTagNo()) {
                        ASN1OctetString keyHashOctetString = (ASN1OctetString) derTaggedObject.getObject();
                        responderId.setByKey(keyHashOctetString.getOctets());
                    } else {
                        X509Name name = X509Name.getInstance(derTaggedObject.getObject());
                        responderId.setByName(name.toString());
                    }

                    ocspRefList.add(ocspRef);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
    }

    private void extendSignatureTag(Element signatureEl, UnsignedPropertiesType unsigned) throws IOException {

        XAdESSignature signature = new XAdESSignature(signatureEl);
        X509Certificate signingCertificate = signature.getSigningCertificate();
        Date signingTime = signature.getSigningTime();

        ValidationContext ctx = certificateVerifier.validateCertificate(signingCertificate, signingTime,
                new XAdESCertificateSource(signatureEl, false), null, null);

        // XAdES-C: complete certificate refs
        CompleteCertificateRefsType completeCertificateRefs = xadesObjectFactory.createCompleteCertificateRefsType();
        CertIDListType certIdList = xadesObjectFactory.createCertIDListType();
        completeCertificateRefs.setCertRefs(certIdList);
        List<CertIDType> certIds = certIdList.getCert();

        for (int i = 0; i < ctx.getNeededCertificates().size(); i++) {
            X509Certificate certificate = ctx.getNeededCertificates().get(i).getCertificate();
            CertIDType certId = getCertID(certificate, DigestAlgorithm.SHA1);
            LOG.info("Add a reference for Certificate[subjectName=" + certificate.getSubjectDN() + "] : digest="
                    + Hex.encodeHexString(certId.getCertDigest().getDigestValue()) + ",issuer="
                    + certId.getIssuerSerial().getX509IssuerName() + ",serial="
                    + certId.getIssuerSerial().getX509SerialNumber());
            certIds.add(certId);
        }

        // XAdES-C: complete revocation refs
        CompleteRevocationRefsType completeRevocationRefs = xadesObjectFactory.createCompleteRevocationRefsType();

        incorporateCRLRefs(completeRevocationRefs, ctx);
        incorporateOCSPRefs(completeRevocationRefs, ctx);

        /* Remove previous OCSPRefs and CRLRefs tags. */
        Iterator<?> it = unsigned.getUnsignedSignatureProperties()
                .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().iterator();
        while (it.hasNext()) {
            Object e = it.next();
            if (e instanceof CompleteRevocationRefsType || e instanceof CompleteCertificateRefsType) {
                it.remove();
            } else if (e instanceof JAXBElement) {
                e = ((JAXBElement<?>) e).getValue();
                if (e instanceof CompleteRevocationRefsType || e instanceof CompleteCertificateRefsType) {
                    it.remove();
                }
            }
        }

        unsigned.getUnsignedSignatureProperties().getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()
                .add(xadesObjectFactory.createCompleteCertificateRefs(completeCertificateRefs));
        unsigned.getUnsignedSignatureProperties().getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()
                .add(xadesObjectFactory.createCompleteRevocationRefs(completeRevocationRefs));

    }

    protected void extendSignatureTag(Element signatureEl, Document originalData, SignatureFormat signatureFormat) {

        super.extendSignatureTag(signatureEl, originalData, signatureFormat);

        try {

            Element qualifyingProperties = XMLUtils
                    .getElement(signatureEl, "./ds:Object/xades:QualifyingProperties");
            Element unsignedPropertiesNode = XMLUtils.getElement(qualifyingProperties, "./xades:UnsignedProperties");
            Element unsignedSignaturePropertiesNode = XMLUtils.getElement(unsignedPropertiesNode,
                    "./xades:UnsignedSignatureProperties");

            List<Node> toRemove = new ArrayList<Node>();

            if (unsignedSignaturePropertiesNode != null) {
                /* If we change a level C of a previous signature, we need to remove other node than level -T. */
                NodeList children = unsignedSignaturePropertiesNode.getChildNodes();
                for (int i = 0; i < children.getLength(); i++) {
                    Node n = children.item(i);
                    if (n.getNodeType() == Node.ELEMENT_NODE) {
                        Element e = (Element) n;
                        if (!"SignatureTimeStamp".equals(e.getLocalName())) {
                            toRemove.add(e);
                        }
                    }
                }
            }

            /* We replace only if we go to level C, XL */
            if (toRemove.size() == 0 || signatureFormat == SignatureFormat.XAdES_C
                    || signatureFormat == SignatureFormat.XAdES_XL || signatureFormat == SignatureFormat.XAdES_A) {

                for (Node e : toRemove) {
                    LOG.warning("Remove element " + e.getLocalName());
                    unsignedSignaturePropertiesNode.removeChild(e);
                }

                UnsignedPropertiesType unsignedPropertiesType = null;
                if (unsignedPropertiesNode != null) {
                    unsignedPropertiesType = ((JAXBElement<UnsignedPropertiesType>) unmarshaller
                            .unmarshal(unsignedPropertiesNode)).getValue();
                } else {
                    unsignedPropertiesType = xadesObjectFactory.createUnsignedPropertiesType();
                }

                extendSignatureTag(signatureEl, unsignedPropertiesType);

                if (unsignedPropertiesNode != null) {
                    qualifyingProperties.removeChild(unsignedPropertiesNode);
                }

                marshaller.marshal(xadesObjectFactory.createUnsignedProperties(unsignedPropertiesType),
                        qualifyingProperties);

            }
        } catch (JAXBException e) {
            throw new RuntimeException("JAXB error: " + e.getMessage(), e);

        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Gives back the JAXB DigestAlgAndValue data structure.
     * 
     * @param data
     * @param xadesObjectFactory
     * @param xmldsigObjectFactory
     * @param digestAlgorithm
     * @return
     */
    private DigestAlgAndValueType getDigestAlgAndValue(byte[] data, DigestAlgorithm digestAlgorithm) {
        DigestAlgAndValueType digestAlgAndValue = xadesObjectFactory.createDigestAlgAndValueType();

        DigestMethodType digestMethod = getXmldsigObjectFactory().createDigestMethodType();
        digestAlgAndValue.setDigestMethod(digestMethod);
        String xmlDigestAlgorithm = digestAlgorithm.getXmlId();
        digestMethod.setAlgorithm(xmlDigestAlgorithm);

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(digestAlgorithm.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("message digest algo error: " + e.getMessage(), e);
        }
        byte[] digestValue = messageDigest.digest(data);
        digestAlgAndValue.setDigestValue(digestValue);

        return digestAlgAndValue;
    }

    /**
     * Gives back the JAXB CertID data structure.
     * 
     * @param certificate
     * @param xadesObjectFactory
     * @param xmldsigObjectFactory
     * @param digestAlgorithm
     * @return
     */
    private CertIDType getCertID(X509Certificate certificate, DigestAlgorithm digestAlgorithm) {
        CertIDType certId = xadesObjectFactory.createCertIDType();

        X509IssuerSerialType issuerSerial = getXmldsigObjectFactory().createX509IssuerSerialType();
        certId.setIssuerSerial(issuerSerial);
        String issuerName = certificate.getIssuerX500Principal().toString();
        issuerSerial.setX509IssuerName(issuerName);
        issuerSerial.setX509SerialNumber(certificate.getSerialNumber());

        byte[] encodedCertificate;
        try {
            encodedCertificate = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("certificate encoding error: " + e.getMessage(), e);
        }
        DigestAlgAndValueType certDigest = getDigestAlgAndValue(encodedCertificate, digestAlgorithm);
        certId.setCertDigest(certDigest);

        return certId;
    }

}
