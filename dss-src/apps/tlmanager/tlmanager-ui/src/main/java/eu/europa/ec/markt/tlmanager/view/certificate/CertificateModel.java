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

package eu.europa.ec.markt.tlmanager.view.certificate;

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.util.CertificateUtils;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A model for the <code>CertificatePanel</code>.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */
public class CertificateModel {

    private static final Logger LOG = Logger.getLogger(CertificateModel.class.getName());

    private DigitalIdentityListType digitalIdentity;
    private DigitalIdentityType certDI, snDI, skiDI;
    private X509Certificate certificate;
    private boolean sn, ski;
    private boolean skiAvailable;
    
    /**
     * The default constructor for CertificateAdapter.
     * 
     * @param digitalIdentity the digitalIdentity
     */
    public CertificateModel(DigitalIdentityListType digitalIdentity) {
        this.digitalIdentity = digitalIdentity;

        List<DigitalIdentityType> digitalIds = digitalIdentity.getDigitalId();
        if (!digitalIds.isEmpty()) {
            for (DigitalIdentityType di: digitalIds) {
                if (di == null) {
                    continue;
                }
                byte[] x509Certificate = di.getX509Certificate();
                if (x509Certificate != null) {
                    InputStream stream = new ByteArrayInputStream(x509Certificate);
                    try {
                        certificate = CertificateUtils.read(stream);

                    } catch (CertificateException ce) {
                        LOG.log(Level.SEVERE,
                                ">>>General CertificateException while trying to convert! " + ce.getMessage());
                    }
                } else if (di.getX509SubjectName() != null) {
                    sn = true;
                } else if (di.getX509SKI() != null) {
                    ski = true;
                }
            }
        }
        
        updateDigitalIdentity();
    }

    private void alignSDI() {
        List<DigitalIdentityType> digitalId = digitalIdentity.getDigitalId();
        digitalId.clear();  // easier to clear than to iterate
        
        digitalId.add(certDI);

        if (sn) {
            digitalId.add(snDI);
        }
        if (ski) {
            digitalId.add(skiDI);
        }
    }
    
    /**
     * Gets the certificate.
     * 
     * @return the certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the certificate.
     * 
     * @param certificate the certificate to set
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * @param sn the sn to set
     */
    public void setSn(boolean sn) {
        this.sn = sn;
        alignSDI();
    }
    
    /**
     * @param ski the ski to set
     */
    public void setSki(boolean ski) {
        this.ski = ski;
        alignSDI();
    }
    
    /**
     * @return the sn
     */
    public boolean isSn() {
        return sn;
    }

    /**
     * @return the ski
     */
    public boolean isSki() {
        return ski;
    }

    /**
     * @return the skiAvailable
     */
    public boolean isSkiAvailable() {
        return skiAvailable;
    }

    /**
     * Gets the digital identity.
     * 
     * @return the digital identity
     */
    public DigitalIdentityListType getDigitalIdentity() {
        return digitalIdentity;
    }

    /**
     * Updates the <code>DigitalIdentityListType</code> with the data of the <code>X509Certificate</code>.
     */
    public void updateDigitalIdentity() {
        if (certificate != null) {
            // create all possible digital identities from the loaded certificate

            // X509Certificate
            certDI = new DigitalIdentityType();
            try {
                certDI.setX509Certificate(certificate.getEncoded());
            } catch (CertificateEncodingException cee) {
                LOG.log(Level.SEVERE, "Unable to extract certificate! " + cee.getMessage());
            }

            // X509SubjectName
            snDI = new DigitalIdentityType();
            try {
                snDI.setX509SubjectName(certificate.getSubjectDN().getName());
            } catch (NullPointerException npe) {
                LOG.log(Level.SEVERE, "Unable to extract subject name! " + npe.getMessage());
            }

            // X509SKI
            skiDI = new DigitalIdentityType();
            try {
                byte[] skiValue = certificate.getExtensionValue(Configuration.SKI_OID);
                skiAvailable = (skiValue != null && skiValue.length != 0);
                skiDI.setX509SKI(skiValue);
            } catch (NullPointerException npe) {
                LOG.log(Level.WARNING, "Unable to extract ski! " + npe.getMessage());
            }
            
            alignSDI();
        }
    }

    /**
     * Recreates the <code>DigitalIdentityListType</code>.
     * 
     * @return the <code>DigitalIdentityListType</code>
     */
    public DigitalIdentityListType createSDI() {
        alignSDI();
        
        return digitalIdentity;
    }
}