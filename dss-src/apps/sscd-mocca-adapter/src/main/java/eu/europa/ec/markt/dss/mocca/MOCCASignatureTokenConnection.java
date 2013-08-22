package eu.europa.ec.markt.dss.mocca;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.PasswordInputCallback;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import at.gv.egiz.smcc.CardNotSupportedException;
import at.gv.egiz.smcc.SignatureCard;
import at.gv.egiz.smcc.SignatureCard.KeyboxName;
import at.gv.egiz.smcc.SignatureCardFactory;
import at.gv.egiz.smcc.util.SmartCardIO;

public class MOCCASignatureTokenConnection implements SignatureTokenConnection {

    private static final Logger LOG = Logger.getLogger(MOCCASignatureTokenConnection.class.getName());

    private PINGUIAdapter callback;
    private String moccaSignatureAlgorithm;

    private List<SignatureCard> _signatureCards;
    
    /**
     * Use the constructor when the signature algorithm is not known before the connection
     * is opened. You must set the SignatureAlgorithm property of the key after the connection
     * has opened (you can get the SignatureAlgorithm name from the key)
     * The constructor for MOCCASignatureTokenConnection.
     * @param callback provides the PIN
     */
    public MOCCASignatureTokenConnection(PasswordInputCallback callback) {
        this.callback = new PINGUIAdapter(callback);
    }

    /**
     * Use this constructure when the algorithm is known before the connection is opened.
     * The constructor for MOCCASignatureTokenConnection.
     * @param callback
     * @param moccaSignatureAlgorithm (this is the XML form).
     */
    public MOCCASignatureTokenConnection(PasswordInputCallback callback, String moccaSignatureAlgorithm) {
        this.callback = new PINGUIAdapter(callback);

        this.moccaSignatureAlgorithm = moccaSignatureAlgorithm;
    }

    @Override
    public void close() {
        if (_signatureCards != null)
            for (SignatureCard c : _signatureCards) {
                c.disconnect(true);
            }
        _signatureCards.clear();
        _signatureCards = null;
    }

    private List<SignatureCard> getSignatureCards() {
        if (_signatureCards == null) {
            _signatureCards = new ArrayList<SignatureCard>();
            SmartCardIO io = new SmartCardIO();
            SignatureCardFactory factory = SignatureCardFactory.getInstance();

            for (Entry<CardTerminal, Card> entry : io.getCards().entrySet()) {
                try {
                    _signatureCards.add(factory.createSignatureCard(entry.getValue(), entry.getKey()));
                } catch (CardNotSupportedException e) {
                    //just log the error - MOCCA tries to connect to all cards and we may have
                    //an MSCAPI or PKCS11 also inserted.
                    LOG.info(e.getMessage());
                }
            }
        }
        return _signatureCards;
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException {
        List<DSSPrivateKeyEntry> list;
        if (getSignatureCards().size()<=1 && moccaSignatureAlgorithm!=null){
            list = getKeysSingleCard();
        } else {
            list = getKeysSeveralCards();
        }
        
        if (list.size() == 0) {
            throw new KeyStoreException("Cannot retrieve keys");
        }
        return list;

    }
    private List<DSSPrivateKeyEntry> getKeysSingleCard(){
        List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();
        SignatureCard sc = getSignatureCards().get(0);
        try {
            byte[] data = sc.getCertificate(KeyboxName.SECURE_SIGNATURE_KEYPAIR, callback);
            if (data != null) {
                list.add(new MOCCAPrivateKeyEntry(data, KeyboxName.SECURE_SIGNATURE_KEYPAIR,moccaSignatureAlgorithm));
            }
        } catch (Exception e) {
            LOG.log(Level.SEVERE, e.getMessage(), e);
        }
        try {
            byte[] data = sc.getCertificate(KeyboxName.CERTIFIED_KEYPAIR, callback);
            if (data != null) {
                list.add(new MOCCAPrivateKeyEntry(data, KeyboxName.CERTIFIED_KEYPAIR, moccaSignatureAlgorithm));
            }
        } catch (Exception e) {
            LOG.log(Level.SEVERE, e.getMessage(), e);
        }
        return list;
    }
    
    private List<DSSPrivateKeyEntry> getKeysSeveralCards() throws KeyStoreException{
        List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

        int counter = 0;
        for (SignatureCard sc : getSignatureCards()) {
            try {
                byte[] data = sc.getCertificate(KeyboxName.SECURE_SIGNATURE_KEYPAIR, callback);
                if (data != null) {
                    list.add(new MOCCAPrivateKeyEntry(data, KeyboxName.SECURE_SIGNATURE_KEYPAIR, counter, sc.getCard()
                            .getATR().getBytes()));
                }
            } catch (Exception e) {
                LOG.log(Level.SEVERE, e.getMessage(), e);
            }
            counter++;
        }
        counter = 0;
        for (SignatureCard sc : getSignatureCards()) {
            try {
                byte[] data = sc.getCertificate(KeyboxName.CERTIFIED_KEYPAIR, callback);
                if (data != null) {
                    list.add(new MOCCAPrivateKeyEntry(data, KeyboxName.CERTIFIED_KEYPAIR, counter, sc.getCard()
                            .getATR().getBytes()));
                }
            } catch (Exception e) {
                LOG.log(Level.SEVERE, e.getMessage(), e);
            }
            counter++;
        }

        return list;
    }

    @Override
    public byte[] sign(InputStream stream, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry)
            throws NoSuchAlgorithmException, IOException {

        if (!(keyEntry instanceof MOCCAPrivateKeyEntry)) {
            throw new RuntimeException("Unsupported DSSPrivateKeyEntry instance " + keyEntry.getClass());
        }
        MOCCAPrivateKeyEntry moccaKey = (MOCCAPrivateKeyEntry) keyEntry;

        try {
            if (_signatureCards == null) {
                throw new IllegalStateException("The cards have not been initialised");
            }
            if (moccaKey.getPos() > _signatureCards.size() - 1) {

                throw new IllegalStateException("Card was removed or disconnected " + moccaKey.getPos() + " "
                        + _signatureCards.size());
            }
            if (moccaKey.getMoccaSignatureAlgorithm() == null) {
                throw new IllegalStateException("The signature algorithm has not been initialised");
            }
            return _signatureCards.get(moccaKey.getPos()).createSignature(stream, moccaKey.getKeyboxName(), callback,
                    moccaKey.getMoccaSignatureAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public int getRetries() {
        return callback.getRetries();
    }
}
