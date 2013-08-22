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

package eu.europa.ec.markt.dss.validation.tsl;

import eu.europa.ec.markt.dss.CannotFetchDataException;
import eu.europa.ec.markt.dss.EncodingException;
import eu.europa.ec.markt.dss.EncodingException.MSG;
import eu.europa.ec.markt.dss.NotETSICompliantException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.ConfigurationException;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * 
 * Certificate coming from the Trusted List
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class TrustedListsCertificateSource implements CertificateSource {

    private static final Logger LOG = Logger.getLogger(TrustedListsCertificateSource.class.getName());

    private String lotlUrl;

    private HTTPDataLoader tslLoader;

    private Map<X500Principal, List<CertificateAndContext>> certificates;

    private boolean checkSignature = true;

    private Resource lotlCertificate;

    /**
     * The default constructor for TrustedListsCertificateSource.
     */
    public TrustedListsCertificateSource() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @param tslLoader the tslLoader to set
     */
    public void setTslLoader(HTTPDataLoader tslLoader) {
        this.tslLoader = tslLoader;
    }

    /**
     * @param lotlCertificate the lotlCertificate to set
     */
    public void setLotlCertificate(Resource lotlCertificate) {
        this.lotlCertificate = lotlCertificate;
    }

    /**
     * @return the certificates
     */
    public Map<X500Principal, List<CertificateAndContext>> getCertificates() {
        return certificates;
    }

    @Override
    public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {
        LOG.log(Level.FINE, "Looking for {0} in {1}", new Object[] { subjectName, certificates.values() });
        return certificates.get(subjectName);
    }

    /**
     * Define if we must check the TL signature
     * 
     * @param checkSignature the checkSignature to set
     */
    public void setCheckSignature(boolean checkSignature) {
        this.checkSignature = checkSignature;
    }

    /**
     * Define the URL of the LOTL
     * 
     * @param lotlUrl the lotlUrl to set
     */
    public void setLotlUrl(String lotlUrl) {
        this.lotlUrl = lotlUrl;
    }

    /**
     * Load the certificates contained in all the TSL referenced by the LOTL
     * 
     * @throws IOException
     */
    public void init() throws IOException, ConfigurationException, CannotFetchDataException {
        certificates = new HashMap<X500Principal, List<CertificateAndContext>>();

        X509Certificate lotlCert = null;
        if (checkSignature) {

            if (lotlCertificate == null) {
                throw new ConfigurationException(
                        "The lotlCertificate property must contains a reference to the LOTL signer's certificate. ");
            }

            CertificateFactory factory = null;
            try {
                factory = CertificateFactory.getInstance("X509");
            } catch (CertificateException e1) {
                throw new ConfigurationException("Platform don't support X509 certificate");
            }

            try {
                lotlCert = (X509Certificate) factory.generateCertificate(lotlCertificate.getInputStream());
            } catch (CertificateException e1) {
                throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
            }
        }

        LOG.log(Level.INFO, "Loading LOTL from " + lotlUrl);
        TrustStatusList lotl = null;
        try {
            lotl = getTrustStatusList(lotlUrl, lotlCert);
        } catch (NotETSICompliantException e) {
            LOG.severe("TSL not compliant with ETSI " + e.getMessage());
        }

        for (PointerToOtherTSL p : lotl.getOtherTSLPointers()) {

            try {

                X509Certificate cert = p.getDigitalId();
                boolean wellSigned = true; 
                if (cert == null) {
                    LOG.severe("No certificate for TSL of territory " + p.getTerritory());
                    wellSigned = false;
                }

                LOG.info("Loading TrustStatusList from " + p.getTerritory() + " url= " + p.getTslLocation());
                TrustStatusList countryTSL = getTrustStatusList(p.getTslLocation(), cert);
                loadAllCertificatesFromOneTSL(countryTSL, wellSigned);

            } catch (CannotFetchDataException ex) {
                LOG.log(Level.SEVERE, "Error when reading TSL", ex);
            } catch (CertificateException ex) {
                LOG.log(Level.SEVERE, "Cannot read certificate from pointer to " + p.getTerritory(), ex);
            } catch (IOException ex) {
                LOG.log(Level.SEVERE, "Error when reading TSL", ex);
            } catch (NotETSICompliantException e) {
                LOG.severe("TSL not compliant with ETSI " + e.getMessage());
            }
        }

    }

    /**
     * Add all the service entry (current and history) of all the providers of the trusted list to the list of
     * CertificateSource
     * 
     * @param tsl
     */
    private void loadAllCertificatesFromOneTSL(TrustStatusList tsl, boolean wellSigned) {
        for (TrustServiceProvider p : tsl.getTrustServicesProvider()) {
            for (AbstractTrustService s : p.getTrustServiceList()) {
                for (X509Certificate c : s.getDigitalIdentity()) {
                    addCertificate(c, s, p, wellSigned);
                }
            }
        }
    }

    /**
     * Add a service entry (current or history) to the list of CertificateAndContext
     * 
     * @param cert
     * @param s
     * @param provider
     */
    private void addCertificate(X509Certificate cert, AbstractTrustService s, TrustServiceProvider provider, boolean wellsigned) {
        List<CertificateAndContext> list = certificates.get(cert.getSubjectX500Principal());
        if (list == null) {
            list = new ArrayList<CertificateAndContext>();
            certificates.put(cert.getSubjectX500Principal(), list);
        }
        CertificateAndContext ctx = new CertificateAndContext();
        ctx.setCertificate(cert);
        ctx.setCertificateSource(CertificateSourceType.TRUSTED_LIST);

        try {
            ServiceInfo info = s.createServiceInfo();
            info.setCurrentStatus(s.getCurrentServiceInfo().getStatus());
            info.setCurrentStatusStartingDate(s.getCurrentServiceInfo().getStatusStartDate());
            info.setServiceName(s.getServiceName());
            info.setStatusAtReferenceTime(s.getStatus());
            info.setStatusStartingDateAtReferenceTime(s.getStatusStartDate());
            info.setStatusEndingDateAtReferenceTime(s.getStatusEndDate());
            info.setTspElectronicAddress(provider.getElectronicAddress());
            info.setTspName(provider.getName());
            info.setTspPostalAddress(provider.getPostalAddress());
            info.setTspTradeName(provider.getTradeName());
            info.setType(s.getType());
            info.setTlWellSigned(wellsigned);
            ctx.setContext(info);
            list.add(ctx);
        } catch (NotETSICompliantException ex) {
            LOG.log(Level.SEVERE,
                    "The entry for " + s.getServiceName() + " don't respect ESTI specification " + ex.getMessage());
        }
    }

    /**
     * Load a trusted list for the specified URL
     * 
     * @param url
     * @param signerIdentity
     * @return
     * @throws IOException
     */
    private TrustStatusList getTrustStatusList(String url, X509Certificate signerIdentity) throws IOException, CannotFetchDataException {
        try {
            InputStream input = tslLoader.get(url);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(input);
            input.close();

            boolean coreValidity = false; 
                
            if (signerIdentity != null && checkSignature) {
                NodeList signatureNodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

                if (signatureNodeList.getLength() == 0) {
                    throw new NotETSICompliantException(
                            eu.europa.ec.markt.dss.NotETSICompliantException.MSG.TSL_NOT_SIGNED);
                }
                if (signatureNodeList.getLength() > 1) {
                    throw new NotETSICompliantException(
                            eu.europa.ec.markt.dss.NotETSICompliantException.MSG.MORE_THAN_ONE_SIGNATURE);
                }

                final Element signatureEl = (Element) signatureNodeList.item(0);

                try {
                    DOMValidateContext valContext = new DOMValidateContext(
                            KeySelector.singletonKeySelector(signerIdentity.getPublicKey()), signatureEl);
                    valContext.setURIDereferencer(new URIDereferencer() {

                        @Override
                        public Data dereference(URIReference uriReference, XMLCryptoContext context)
                                throws URIReferenceException {
                            try {
                                final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                                        new XMLDSigRI());
                                return fac.getURIDereferencer().dereference(uriReference, context);
                            } catch (URIReferenceException ex) {
                                if (uriReference.getType().equals(
                                        "http://uri.etsi.org/01903/v1.1.1#SignedProperties")) {
                                    final Element signedProperties = getElement(signatureEl,
                                            "./ds:Object/xades:QualifyingProperties/xades:SignedProperties");
                                    if (signedProperties != null) {
                                        return new NodeSetData() {
                                            @Override
                                            public Iterator<?> iterator() {
                                                return Arrays.asList(signedProperties).iterator();
                                            }
                                        };
                                    }
                                    final Element signedProperties111 = getElement(signatureEl,
                                            "./ds:Object/etsi:QualifyingProperties/etsi:SignedProperties");
                                    if (signedProperties111 != null) {
                                        return new NodeSetData() {
                                            @Override
                                            public Iterator<?> iterator() {
                                                return Arrays.asList(signedProperties111).iterator();
                                            }
                                        };
                                    }
                                }
                                throw ex;
                            }
                        }
                    });
                    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
                    XMLSignature signature = factory.unmarshalXMLSignature(valContext);
                    coreValidity = signature.validate(valContext);

                    LOG.fine("TSL " + url + " well signed");
                } catch (XMLSignatureException ex) {
                    throw new RuntimeException("Problem validating signature of " + url, ex);
                } catch (MarshalException e) {
                    throw new RuntimeException("Problem validating signature of " + url, e);
                }

            }

            TrustStatusList tsl = TrustServiceListFactory.newInstance(doc);
            tsl.setWellSigned(coreValidity);
            return tsl;
        } catch (ParserConfigurationException ex) {
            LOG.log(Level.SEVERE, "Error in TSL parsing " + ex.getMessage(), ex);
            throw new RuntimeException(ex);
        } catch (SAXException e) {
            throw new NotETSICompliantException(eu.europa.ec.markt.dss.NotETSICompliantException.MSG.NOT_A_VALID_XML);
        }
    }

    private XPathExpression createXPathExpression(String xpathString) {
        /* XPath */
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {

            @Override
            public Iterator<?> getPrefixes(String namespaceURI) {
                throw new RuntimeException();
            }

            @Override
            public String getPrefix(String namespaceURI) {
                throw new RuntimeException();
            }

            @Override
            public String getNamespaceURI(String prefix) {
                if ("ds".equals(prefix)) {
                    return XMLSignature.XMLNS;
                } else if ("etsi".equals(prefix)) {
                    return "http://uri.etsi.org/01903/v1.1.1#";
                } else if ("xades".equals(prefix)) {
                    return "http://uri.etsi.org/01903/v1.3.2#";
                } else if ("xades141".equals(prefix)) {
                    return "http://uri.etsi.org/01903/v1.4.1#";
                }
                throw new RuntimeException("Prefix not recognized : " + prefix);
            }
        });
        try {
            XPathExpression expr = xpath.compile(xpathString);
            return expr;
        } catch (XPathExpressionException ex) {
            throw new RuntimeException(ex);
        }

    }

    /**
     * Return the Element corresponding the the XPath
     * 
     * @param xmlNode
     * @param xpathString
     * @return
     * @throws XPathExpressionException
     */
    private Element getElement(Node xmlNode, String xpathString) {
        XPathExpression expr = createXPathExpression(xpathString);
        NodeList list;
        try {
            list = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
            if (list.getLength() > 1) {
                throw new RuntimeException("More than one result for XPath: " + xpathString);
            }
            return (Element) list.item(0);
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        }
    }

}
