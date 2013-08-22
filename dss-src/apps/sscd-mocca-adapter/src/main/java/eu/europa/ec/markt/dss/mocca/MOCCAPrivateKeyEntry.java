package eu.europa.ec.markt.dss.mocca;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import at.gv.egiz.smcc.SignatureCard.KeyboxName;
/**
 * 
 * A DSSPrivateKeyEntry implementation for the MOCCA framework
 *  
 */
public class MOCCAPrivateKeyEntry implements DSSPrivateKeyEntry {

    private X509Certificate token;

    private KeyboxName keyboxName;

    private String moccaSignatureAlgorithm;

    private int pos;

    private final byte[] atr;

    private SignatureAlgorithm signatureAlgorithm;


    /**
     * 
     * Constructure when working with several cards
     * @param cert the certificate
     * @param keyboxName identifies signature usage/algo
     * @param pos the position of this KeyEntry in the overall list
     * @param atr the ATR associated with this key
     * @throws Exception
     */
    public MOCCAPrivateKeyEntry(byte[] cert, KeyboxName keyboxName, int pos, byte[] atr) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X509", new BouncyCastleProvider());
        token = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert));
        this.keyboxName = keyboxName;
        this.pos = pos;
        this.atr = atr;
    }
    
    /**
     * Constructor when using only one card
     * @param cert the certificate
     * @param keyboxName identifies signature usage/algo
     * @param moccaSignatureAlgorithm the signature algorithm to use
     * @throws Exception
     */
    public MOCCAPrivateKeyEntry(byte[] cert, KeyboxName keyboxName, String moccaSignatureAlgorithm) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X509", new BouncyCastleProvider());
        token = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert));
        this.keyboxName = keyboxName;
        this.moccaSignatureAlgorithm = moccaSignatureAlgorithm;
        this.atr = null;
    }
    @Override
    public X509Certificate getCertificate() {
        return token;
    }

    @Override
    public Certificate[] getCertificateChain() {
        return null;
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm() throws NoSuchAlgorithmException {
        return signatureAlgorithm;
    }

    /**
     * Set the signature algorithm
     * @param the signature algorithm to set
     */
    public void setSignatureAlgorithm(SignatureAlgorithm sa) {
        signatureAlgorithm = sa;
    }

    /**
     * Gets the X509 Signature algorithm name
     * 
     * @return the name (something like SHA1WithRSA)
     */
    public String getX509SignatureAlgorithmName() {
        return token.getSigAlgName();
    }

    /**
     * @return the moccaSignatureAlgorithm (something like "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
     */
    public String getMoccaSignatureAlgorithm() {
        return moccaSignatureAlgorithm;
    }

    public void setMoccaSignatureAlgorithm(String s) {
        this.moccaSignatureAlgorithm = s;
    }

    /**
     * @return the keyboxName
     */
    public KeyboxName getKeyboxName() {
        return keyboxName;
    }

    /**
     * Gets the position of this key in the list of all keys
     * @return
     */
    public int getPos() {
        return pos;
    }

    /**
     * Get the ATR associated with this key
     * @return the ATR
     */
    public byte[] getAtr() {
        return atr;
    }
}
