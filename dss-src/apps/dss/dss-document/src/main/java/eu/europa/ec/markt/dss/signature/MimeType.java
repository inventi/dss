/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/dss/dss-document/src/main/java/eu/europa/ec/markt/dss/signature/MimeType.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.dss.signature;

/**
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public enum MimeType {

    BINARY("application/octet-stream"), XML("text/xml"), PDF("application/pdf"), PKCS7("application/pkcs7-signature"),
    PLAIN("text/plain");

    private String code;

    /**
     * The default constructor for MimeTypes.
     */
    private MimeType(String code) {
        this.code = code;
    }

    /**
     * @return the code
     */
    public String getCode() {
        return code;
    }

    public static MimeType fromFileName(String name) {
        if (name.toLowerCase().endsWith(".xml")) {
            return XML;
        } else if (name.toLowerCase().endsWith(".pdf")) {
            return PDF;
        } else {
            return BINARY;
        }
    }

}
