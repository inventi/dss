/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/tlmanager/tlmanager-ui/src/main/java/eu/europa/ec/markt/tlmanager/util/CertificateUtils.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.tlmanager.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Read certificate with BC
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class CertificateUtils {

    private static final Logger LOG = Logger.getLogger(CertificateUtils.class.getName());

    public static X509Certificate read(byte[] data) throws CertificateException {
        return read(new ByteArrayInputStream(data));
    }

    public static X509Certificate read(InputStream stream) throws CertificateException {
        try {
            Security.addProvider(new BouncyCastleProvider());
            CertificateFactory factory;
            factory = CertificateFactory.getInstance("X509", "BC");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(stream);
            return cert;
        } catch (NoSuchProviderException ex) {
            LOG.log(Level.WARNING, "Unable to load the certificate! " + ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

}
