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

package eu.europa.ec.markt.dss.validation.crl;

import eu.europa.ec.markt.dss.CannotFetchDataException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.NoSuchParserException;
import org.bouncycastle.x509.util.StreamParsingException;

/**
 * Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class OnlineCRLSource implements CRLSource {

    private static final Logger LOG = Logger.getLogger(OnlineCRLSource.class.getName());

    private HTTPDataLoader urlDataLoader;

    /**
     * Set the HTTPDataLoader to use for query the CRL server
     * 
     * @param urlDataLoader
     */
    public void setUrlDataLoader(HTTPDataLoader urlDataLoader) {
        this.urlDataLoader = urlDataLoader;
    }

    @Override
    public X509CRL findCrl(X509Certificate certificate, X509Certificate issuerCertificate) {
        try {
            String crlURL = getCrlUri(certificate);
            LOG.info("CRL's URL for " + certificate.getSubjectDN() + " : " + crlURL);
            if (crlURL == null) {
                return null;
            }
            if (crlURL.startsWith("http://") || crlURL.startsWith("https://")) {
                return getCrl(crlURL);
            } else {
                LOG.warning("We support only HTTP and HTTPS CRL's url, this url is " + crlURL);
                return null;
            }
        } catch (CRLException e) {
            LOG.severe("error parsing CRL: " + e.getMessage());
            throw new RuntimeException(e);
        } catch (MalformedURLException e) {
            LOG.severe("error parsing CRL: " + e.getMessage());
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            LOG.severe("error parsing CRL: " + e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            /*
             * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment
             * for this exception
             */
            LOG.severe("error parsing CRL: " + e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchParserException e) {
            LOG.severe("error parsing CRL: " + e.getMessage());
            throw new RuntimeException(e);
        } catch (StreamParsingException e) {
            LOG.severe("error parsing CRL: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private X509CRL getCrl(String downloadUrl) throws CertificateException, CRLException, NoSuchProviderException,
            NoSuchParserException, StreamParsingException {

        if (downloadUrl != null) {
            try {
                InputStream input = urlDataLoader.get(downloadUrl);

                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) certificateFactory.generateCRL(input);
                LOG.fine("CRL size: " + crl.getEncoded().length + " bytes");
                return crl;
            } catch (CannotFetchDataException ioe) {
                return null;
            }
        } else {
            return null;
        }
    }

    /**
     * Gives back the CRL URI meta-data found within the given X509 certificate.
     * 
     * @param certificate the X509 certificate.
     * @return the CRL URI, or <code>null</code> if the extension is not present.
     * @throws MalformedURLException
     */
    @SuppressWarnings("deprecation")
    public String getCrlUri(X509Certificate certificate) throws MalformedURLException {
        byte[] crlDistributionPointsValue = certificate.getExtensionValue(X509Extensions.CRLDistributionPoints
                .getId());
        if (null == crlDistributionPointsValue) {
            return null;
        }
        ASN1Sequence seq;
        try {
            DEROctetString oct;
            oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointsValue))
                    .readObject());
            seq = (ASN1Sequence) new ASN1InputStream(oct.getOctets()).readObject();
        } catch (IOException e) {
            throw new RuntimeException("IO error: " + e.getMessage(), e);
        }
        CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
        DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
        for (DistributionPoint distributionPoint : distributionPoints) {
            DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
            if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {
                continue;
            }
            GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
            GeneralName[] names = generalNames.getNames();
            for (GeneralName name : names) {
                if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    LOG.fine("not a uniform resource identifier");
                    continue;
                }
                String str = null;
                if (name.getDERObject() instanceof DERTaggedObject) {
                    DERTaggedObject taggedObject = (DERTaggedObject) name.getDERObject();
                    DERIA5String derStr = DERIA5String.getInstance(taggedObject.getObject());
                    str = derStr.getString();
                } else {
                    DERIA5String derStr = DERIA5String.getInstance(name.getDERObject());
                    str = derStr.getString();
                }
                if (str != null && (str.startsWith("http://") || str.startsWith("https://"))) {
                    return str;
                } else {
                    LOG.info("Supports only http:// and https:// protocol for CRL");
                }
            }
        }
        return null;
    }

}
