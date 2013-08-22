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

package eu.europa.ec.markt.dss.validation.xades;

import eu.europa.ec.markt.dss.EncodingException;
import eu.europa.ec.markt.dss.EncodingException.MSG;
import eu.europa.ec.markt.dss.NotETSICompliantException;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.provider.SpecialPrivateKey;
import eu.europa.ec.markt.dss.signature.xades.OneExternalFileURIDereferencer;
import eu.europa.ec.markt.dss.signature.xades.XMLUtils;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureFormat;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken.TimestampType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.jcp.xml.dsig.internal.dom.DOMReference;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * 
 * Parse an XAdES structure
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(XAdESSignature.class.getName());

    public static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

    private Element signatureElement;

    /**
     * @return the signatureElement
     */
    public Element getSignatureElement() {
        return signatureElement;
    }
    
    /**
     * 
     * The default constructor for XAdESSignature.
     * 
     * @param signatureElement
     */
    public XAdESSignature(Element signatureElement) {
        Init.init();
        if (signatureElement == null) {
            throw new NullPointerException("Must provide a signatureElement");
        }
        this.signatureElement = signatureElement;
    }

    @Override
    public SignatureFormat getSignatureFormat() {
        return SignatureFormat.XAdES;
    }

    @Override
    public String getSignatureAlgorithm() {
        try {
            return XMLUtils.getElement(signatureElement, "./ds:SignedInfo/ds:SignatureMethod").getAttribute(
                    "Algorithm");
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.SIGNATURE_METHOD_ERROR);
        }
    }

    @Override
    public XAdESCertificateSource getCertificateSource() {
        return new XAdESCertificateSource(signatureElement, false);
    }

    @Override
    public CertificateSource getExtendedCertificateSource() {
        return new XAdESCertificateSource(signatureElement, true);
    }

    @Override
    public XAdESCRLSource getCRLSource() {
        return new XAdESCRLSource(signatureElement);
    }

    @Override
    public XAdESOCSPSource getOCSPSource() {
        return new XAdESOCSPSource(signatureElement);
    }

    @Override
    public X509Certificate getSigningCertificate() {
        try {
            NodeList list = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/"
                            + "xades:SigningCertificate/xades:Cert");

            for (int i = 0; i < list.getLength(); i++) {
                Element el = (Element) list.item(i);
                Element issuerSubjectNameEl = XMLUtils.getElement(el, "./xades:IssuerSerial/ds:X509IssuerName");
                X500Name issuerName = new X500Name(issuerSubjectNameEl.getTextContent());
                for (X509Certificate c :  getCertificateSource().getCertificates()) {
                    X500Name cIssuer = new X500Name(c.getIssuerX500Principal().getName());
                    if (cIssuer.equals(issuerName)) {
                        return c;
                    }
                }
            }

            return null;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.SIGNING_CERTIFICATE_ENCODING);
        }
    }

    @Override
    public Date getSigningTime() {
        try {

            Element signingTimeEl = XMLUtils.getElement(signatureElement,
                    "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/"
                            + "./xades:SigningTime");
            if (signingTimeEl == null) {
                return null;
            }
            String text = signingTimeEl.getTextContent();
            DatatypeFactory factory = DatatypeFactory.newInstance();
            XMLGregorianCalendar cal = factory.newXMLGregorianCalendar(text);
            return cal.toGregorianCalendar().getTime();
        } catch (DOMException e) {
            throw new RuntimeException(e);
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.SIGNING_TIME_ENCODING);
        }
    }

    @Override
    public PolicyValue getPolicyId() {
        try {
            Element policyId = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/"
                            + "xades:SignaturePolicyIdentifier");
            if (policyId != null) {
                /* There is a policy */
                Element el = XMLUtils.getElement(policyId,
                        "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
                if (el != null) {
                    /* Explicit policy */
                    return new PolicyValue(el.getTextContent());
                } else {
                    /* Implicit policy */
                    return new PolicyValue();
                }
            } else {
                return null;
            }
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.SIGNATURE_POLICY_ENCODING);
        }
    }

    @Override
    public String getLocation() {
        return null;
    }

    @Override
    public String[] getClaimedSignerRoles() {

        NodeList list = XMLUtils.getNodeList(signatureElement,
                "ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/"
                        + "xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole");

        if (list.getLength() == 0) {
            return null;
        }

        String[] roles = new String[list.getLength()];
        for (int i = 0; i < list.getLength(); i++) {
            roles[i] = ((Element) list.item(i)).getTextContent();
        }

        return roles;

    }

    @Override
    public String getContentType() {
        return "text/xml";
    }

    private TimestampToken makeTimestampToken(Element el, TimestampToken.TimestampType timestampType)
            throws XPathExpressionException {
        Element timestampTokenNode = XMLUtils.getElement(el, "./xades:EncapsulatedTimeStamp");
        try {
            byte[] tokenbytes = Base64.decodeBase64(timestampTokenNode.getTextContent());
            TimeStampToken tstoken = new TimeStampToken(new CMSSignedData(tokenbytes));
            return new TimestampToken(tstoken, timestampType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private List<TimestampToken> findTimestampTokens(String elementName, TimestampToken.TimestampType timestampType)
            throws XPathExpressionException {
        NodeList timestampsNodes = this.signatureElement.getElementsByTagName(elementName);
        List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();

        for (int i = 0; i < timestampsNodes.getLength(); i++) {
            TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i), timestampType);
            if (tstoken != null) {
                signatureTimestamps.add(tstoken);
            }
        }

        return signatureTimestamps;
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() {
        try {

            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:SignatureTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {
                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i),
                        TimestampType.SIGNATURE_TIMESTAMP);
                if (tstoken != null) {
                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;

        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.SIGNATURE_TIMESTAMP_ENCODING);
        }
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {
        try {
            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:SigAndRefsTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {
                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i),
                        TimestampToken.TimestampType.VALIDATION_DATA_TIMESTAMP);
                if (tstoken != null) {
                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X1_ENCODING);
        }
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {
        try {
            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:RefsOnlyTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {
                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i),
                        TimestampToken.TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
                if (tstoken != null) {
                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X2_ENCODING);
        }
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {
        try {
            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades141:ArchiveTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {
                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i),
                        TimestampToken.TimestampType.ARCHIVE_TIMESTAMP);
                if (tstoken != null) {
                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.ARCHIVE_TIMESTAMP_ENCODING);
        }
    }

    @Override
    public List<X509Certificate> getCertificates() {
        return getCertificateSource().getCertificates();
    }

    @Override
    public boolean checkIntegrity(Document detachedDocument) {

        DOMValidateContext valContext = new DOMValidateContext(
                KeySelector.singletonKeySelector(getSigningCertificate().getPublicKey()), this.signatureElement);
        
        if (detachedDocument != null) {
            valContext.setURIDereferencer(new OneExternalFileURIDereferencer("detached-file", detachedDocument));
        }
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        try {
            XMLSignature signature = factory.unmarshalXMLSignature(valContext);
            recursiveIdBrowse(valContext, signatureElement);
            boolean r = signature.validate(valContext);
            return r;
        } catch (MarshalException e) {
            throw new RuntimeException(e);
        } catch (XMLSignatureException e) {
            throw new RuntimeException(e);
        }
    }
    
    private void recursiveIdBrowse(DOMValidateContext context, Element element) {
        for(int i = 0 ; i < element.getChildNodes().getLength() ; i++) {
            Node node = element.getChildNodes().item(i);
            if(node.getNodeType() == Node.ELEMENT_NODE) {
                Element childEl = (Element) node;
                if(childEl.hasAttribute("Id")) {
                    context.setIdAttributeNS(childEl, null, "Id");
                }
                recursiveIdBrowse(context, childEl);
            }
        }
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {
        // see ETSI TS 101 903 V1.4.2 (2010-12) pp. 38/39/40
        
        try {
            NodeList counterSigs = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                    + "/xades:CounterSignature");
            if (counterSigs == null) {
                return null;
            }
            
            List<AdvancedSignature> xadesList = new ArrayList<AdvancedSignature>();
            
            for (int i = 0; i < counterSigs.getLength(); i++) {
                Element counterSigEl = (Element) counterSigs.item(i);
                Element signatureEl = XMLUtils.getElement(counterSigEl, "./ds:Signature");

                // Verify that the element is a proper signature by trying to build a XAdESSignature out of it
                XAdESSignature xCounterSig = new XAdESSignature(signatureEl);

                // Verify that there is a ds:Reference element with a Type set to: http://uri.etsi.org/01903#CountersignedSignature
                // (as per the XAdES spec)
                XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
                XMLSignature signature = factory.unmarshalXMLSignature(new DOMStructure(signatureEl));

                LOG.info("Verifying countersignature References");
                for (Object refobj : signature.getSignedInfo().getReferences()) {
                    Reference ref = (Reference) refobj;
                    if (ref.getType() != null && ref.getType().equals("http://uri.etsi.org/01903#CountersignedSignature")) {
                        // Ok, this seems to be a countersignature

                        // Verify that the digest is that of the signature value
                        if (ref.validate(new DOMValidateContext(xCounterSig.getSigningCertificate().getPublicKey(),
                          XMLUtils.getElement(signatureElement, "./ds:SignatureValue")))) {

                            LOG.info("Reference verification succeeded, adding countersignature");
                            xadesList.add(xCounterSig);
                        } else {
                            LOG.warning("Skipping countersignature because the Reference doesn't contain a hash of the embedding SignatureValue");
                        }

                        break;
                    }
                }
            }
            
            return xadesList;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING);
        } catch (MarshalException e) {
            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING);
        } catch (XMLSignatureException e) {
            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING);
        }

    }

    @Override
    public List<CertificateRef> getCertificateRefs() {

        try {

            Element signingCertEl = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:CompleteCertificateRefs/xades:CertRefs");
            if (signingCertEl == null) {
                return null;
            }

            List<CertificateRef> certIds = new ArrayList<CertificateRef>();
            NodeList certIdnodes = XMLUtils.getNodeList(signingCertEl, "./xades:Cert");
            for (int i = 0; i < certIdnodes.getLength(); i++) {
                Element certId = (Element) certIdnodes.item(i);
                Element issuerNameEl = XMLUtils.getElement(certId, "./xades:IssuerSerial/ds:X509IssuerName");
                Element issuerSerialEl = XMLUtils.getElement(certId, "./xades:IssuerSerial/ds:X509SerialNumber");
                Element digestAlgorithmEl = XMLUtils.getElement(certId, "./xades:CertDigest/ds:DigestMethod");
                Element digestValueEl = XMLUtils.getElement(certId, "./xades:CertDigest/ds:DigestValue");

                CertificateRef genericCertId = new CertificateRef();
                if (issuerNameEl != null && issuerSerialEl != null) {
                    genericCertId.setIssuerName(issuerNameEl.getTextContent());
                    genericCertId.setIssuerSerial(issuerSerialEl.getTextContent());
                }

                String algorithm = digestAlgorithmEl.getAttribute("Algorithm");
                genericCertId.setDigestAlgorithm(getShortAlgoName(algorithm));

                genericCertId.setDigestValue(Base64.decodeBase64(digestValueEl.getTextContent()));
                certIds.add(genericCertId);
            }

            return certIds;

        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.CERTIFICATE_REF_ENCODING);
        }
    }

    private String getShortAlgoName(String longAlgoName) {
        if (DigestMethod.SHA1.equals(longAlgoName)) {
            return "SHA1";
        } else if (DigestMethod.SHA256.equals(longAlgoName)) {
            return "SHA256";
        } else if (DigestMethod.SHA512.equals(longAlgoName)) {
            return "SHA512";
        } else {
            throw new RuntimeException("Algorithm " + longAlgoName + " not supported");
        }
    }

    @Override
    public List<CRLRef> getCRLRefs() {

        try {
            List<CRLRef> certIds = new ArrayList<CRLRef>();

            Element signingCertEl = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:CompleteRevocationRefs/xades:CRLRefs");
            if (signingCertEl != null) {

                NodeList certIdnodes = XMLUtils.getNodeList(signingCertEl, "./xades:CRLRef");
                for (int i = 0; i < certIdnodes.getLength(); i++) {
                    Element certId = (Element) certIdnodes.item(i);
                    Element digestAlgorithmEl = XMLUtils.getElement(certId,
                            "./xades:DigestAlgAndValue/ds:DigestMethod");
                    Element digestValueEl = XMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestValue");

                    String algorithm = digestAlgorithmEl.getAttribute("Algorithm");
                    String digestAlgo = getShortAlgoName(algorithm);

                    CRLRef ref = new CRLRef();
                    ref.setAlgorithm(digestAlgo);
                    ref.setDigestValue(Base64.decodeBase64(digestValueEl.getTextContent()));
                    certIds.add(ref);
                }

            }
            return certIds;

        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.CRL_REF_ENCODING);
        }
    }

    @Override
    public List<OCSPRef> getOCSPRefs() {

        try {
            List<OCSPRef> certIds = new ArrayList<OCSPRef>();
            Element signingCertEl = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:CompleteRevocationRefs/xades:OCSPRefs");
            if (signingCertEl != null) {

                NodeList certIdnodes = XMLUtils.getNodeList(signingCertEl, "./xades:OCSPRef");
                for (int i = 0; i < certIdnodes.getLength(); i++) {
                    Element certId = (Element) certIdnodes.item(i);
                    Element digestAlgorithmEl = XMLUtils.getElement(certId,
                            "./xades:DigestAlgAndValue/ds:DigestMethod");
                    Element digestValueEl = XMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestValue");

                    if (digestAlgorithmEl == null || digestValueEl == null) {
                        throw new NotETSICompliantException(
                                eu.europa.ec.markt.dss.NotETSICompliantException.MSG.XADES_DIGEST_ALG_AND_VALUE_ENCODING);
                    }

                    String algorithm = digestAlgorithmEl.getAttribute("Algorithm");
                    String digestAlgo = getShortAlgoName(algorithm);

                    certIds.add(new OCSPRef(digestAlgo, Base64.decodeBase64(digestValueEl.getTextContent()), false));
                }
            }
            return certIds;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.OCSP_REF_ENCODING);
        }

    }

    @Override
    public List<X509CRL> getCRLs() {
        return getCRLSource().getCRLsFromSignature();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {
        return getOCSPSource().getOCSPResponsesFromSignature();
    }

    private byte[] getC14nValue(Node node) {
        try {
            Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
            return c14n.canonicalizeSubtree(node);
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException("c14n algo error: " + e.getMessage(), e);
        } catch (CanonicalizationException e) {
            throw new RuntimeException("c14n error: " + e.getMessage(), e);
        }
    }

    private byte[] getC14nValue(List<Node> nodeList) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            for (Node node : nodeList) {
                Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
                buffer.write(c14n.canonicalizeSubtree(node));
            }
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException("c14n algo error: " + e.getMessage(), e);
        } catch (CanonicalizationException e) {
            throw new RuntimeException("c14n error: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] getSignatureTimestampData() {
        try {
            Element signatureValue = XMLUtils.getElement(signatureElement, "./ds:SignatureValue");
            return getC14nValue(signatureValue);
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.SIGNATURE_TIMESTAMP_DATA_ENCODING);
        }

    }

    @Override
    public byte[] getTimestampX1Data() {
        try {
            List<Node> timeStampNodesXadesX1 = new ArrayList<Node>();
            Element signatureValue = XMLUtils.getElement(signatureElement, "./ds:SignatureValue");
            timeStampNodesXadesX1.add(signatureValue);

            NodeList signatureTimeStampNode = XMLUtils.getNodeList(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:SignatureTimeStamp");
            if (signatureTimeStampNode != null) {
                for (int i = 0; i < signatureTimeStampNode.getLength(); i++) {
                    timeStampNodesXadesX1.add(signatureTimeStampNode.item(i));
                }
            }
            Node completeCertificateRefsNode = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:CompleteCertificateRefs");
            if (completeCertificateRefsNode != null) {
                timeStampNodesXadesX1.add(completeCertificateRefsNode);
            }
            Node completeRevocationRefsNode = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:CompleteRevocationRefs");
            if (completeRevocationRefsNode != null) {
                timeStampNodesXadesX1.add(completeRevocationRefsNode);
            }

            return getC14nValue(timeStampNodesXadesX1);
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X1_DATA_ENCODING);
        }
    }

    @Override
    public byte[] getTimestampX2Data() {
        try {
            List<Node> timeStampNodesXadesX1 = new ArrayList<Node>();
            Node completeCertificateRefsNode = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "/xades:CompleteCertificateRefs");
            if (completeCertificateRefsNode != null) {
                timeStampNodesXadesX1.add(completeCertificateRefsNode);
            }
            Node completeRevocationRefsNode = XMLUtils.getElement(signatureElement,
                    "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
                            + "xades:CompleteRevocationRefs");
            if (completeRevocationRefsNode != null) {
                timeStampNodesXadesX1.add(completeRevocationRefsNode);
            }
            return getC14nValue(timeStampNodesXadesX1);
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X2_DATA_ENCODING);
        }
    }

    @Override
    public byte[] getArchiveTimestampData(int index, Document originalData) throws IOException {

        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            XMLStructure s = new DOMStructure(signatureElement);
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
            DOMXMLSignature signature = (DOMXMLSignature) factory.unmarshalXMLSignature(s);

            DOMSignContext signContext = new DOMSignContext(new SpecialPrivateKey(), signatureElement);
            signContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");
            signContext.setProperty("javax.xml.crypto.dsig.cacheReference", true);
            signContext.setURIDereferencer(new OneExternalFileURIDereferencer("detached-file", originalData));

            // TODO naramsda: check ! Don't let met publish that without further test !!
            // DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // dbf.setNamespaceAware(true);
            // org.w3c.dom.Document xmlDoc = dbf.newDocumentBuilder().newDocument();
            // signature.marshal(xmlDoc.createElement("test"), "ds", signContext);

            for (Object o : signature.getSignedInfo().getReferences()) {
                DOMReference r = (DOMReference) o;
                InputStream data = r.getDigestInputStream();
                if (data != null) {
                    IOUtils.copy(data, buffer);
                }
            }

            List<Node> timeStampNodesXadesA = new LinkedList<Node>();

            Element signedInfo = XMLUtils.getElement(signatureElement, "./ds:SignedInfo");
            timeStampNodesXadesA.add(signedInfo);

            Element signatureValue = XMLUtils.getElement(signatureElement, "./ds:SignatureValue");
            timeStampNodesXadesA.add(signatureValue);

            Element keyInfo = XMLUtils.getElement(signatureElement, "./ds:KeyInfo");
            timeStampNodesXadesA.add(keyInfo);

            Element unsignedSignaturePropertiesNode = getUnsignedSignatureProperties(signatureElement);

            NodeList unsignedProperties = unsignedSignaturePropertiesNode.getChildNodes();
            int count = 0;
            for (int i = 0; i < unsignedProperties.getLength(); i++) {
                if (unsignedProperties.item(i).getNodeType() == Node.ELEMENT_NODE) {
                    Element unsignedProperty = (Element) unsignedProperties.item(i);
                    if ("ArchiveTimeStamp".equals(unsignedProperty.getLocalName())) {
                        if (count == index) {
                            LOG.info("We only need data up to ArchiveTimeStamp index " + index);
                            break;
                        }
                        count++;
                    }
                    timeStampNodesXadesA.add(unsignedProperty);
                }
            }

            buffer.write(getC14nValue(timeStampNodesXadesA));

            return buffer.toByteArray();
//        } catch (ParserConfigurationException e) {
//            throw new IOException("Error when computing the archive data", e);
        } catch (MarshalException e) {
            throw new IOException("Error when computing the archive data", e);
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.ARCHIVE_TIMESTAMP_DATA_ENCODING);
        }
    }

    private Element getUnsignedSignatureProperties(Element signatureEl) {
        try {
            Element unsignedSignaturePropertiesNode = XMLUtils
                    .getElement(signatureEl,
                            "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties");
            if (unsignedSignaturePropertiesNode == null) {
                Element qualifyingProperties = XMLUtils.getElement(signatureEl,
                        "./ds:Object/xades:QualifyingProperties");
                Element unsignedProperties = XMLUtils.getElement(qualifyingProperties,
                        "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties");
                if (unsignedProperties == null) {
                    unsignedProperties = qualifyingProperties.getOwnerDocument().createElementNS(XADES_NAMESPACE,
                            "UnsignedProperties");
                    qualifyingProperties.appendChild(unsignedProperties);
                }
                unsignedSignaturePropertiesNode = unsignedProperties.getOwnerDocument().createElementNS(
                        XADES_NAMESPACE, "UnsignedSignatureProperties");
                unsignedProperties.appendChild(unsignedSignaturePropertiesNode);
            }
            return unsignedSignaturePropertiesNode;
        } catch (XPathExpressionException e) {
            // Should never happens
            throw new RuntimeException("Cannot build unsigned signature properties");
        }

    }

}
