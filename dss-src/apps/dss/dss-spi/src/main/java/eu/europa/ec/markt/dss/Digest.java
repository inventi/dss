/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/dss/dss-spi/src/main/java/eu/europa/ec/markt/dss/Digest.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.dss;

/**
 * Container for a Digest and his algorithm
 *  
 * <p>DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class Digest {

    private DigestAlgorithm algorithm;
    
    private byte[] value;

    /**
     * The default constructor for Digest.
     */
    public Digest() {
    }
    
    public Digest(DigestAlgorithm algorithm, byte[] value) {
        super();
        this.algorithm = algorithm;
        this.value = value;
    }

    /**
     * @return the algorithm
     */
    public DigestAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * @param algorithm the algorithm to set
     */
    public void setAlgorithm(DigestAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * @return the value
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(byte[] value) {
        this.value = value;
    }
    
}
