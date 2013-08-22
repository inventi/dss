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

package eu.europa.ec.markt.dss.signature.token;

import eu.europa.ec.markt.dss.BadPasswordException;
import eu.europa.ec.markt.dss.BadPasswordException.MSG;
import eu.europa.ec.markt.dss.ConfigurationException;
import eu.europa.ec.markt.dss.DigestAlgorithm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * PKCS11 token with callback
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class Pkcs11SignatureToken extends AsyncSignatureTokenConnection {

    private Provider _pkcs11Provider;

    private String pkcs11Path;

    private KeyStore _keyStore;

    final private PasswordInputCallback callback;

    /**
     * Create the SignatureTokenConnection, using the provided path for the library.
     * 
     * @param pkcs11Path
     */
    public Pkcs11SignatureToken(String pkcs11Path) {
        this(pkcs11Path, (PasswordInputCallback) null);
    }

    /**
     * Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the password
     * from the user. The default constructor for CallbackPkcs11SignatureToken.
     * 
     * @param pkcs11Path
     * @param callback
     */
    public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback) {
        this.pkcs11Path = pkcs11Path;
        this.callback = callback;
    }

    /**
     * Sometimes, the password is known in advance. This create a SignatureTokenConnection and the keys will be accessed
     * using the provided password. The default constructor for CallbackPkcs11SignatureToken.
     * 
     * @param pkcs11Path
     * @param password
     */
    public Pkcs11SignatureToken(String pkcs11Path, char[] password) {
        this(pkcs11Path, new PrefilledPasswordCallback(password));
    }

    @SuppressWarnings("restriction")
    private Provider getProvider() {
        try {
            if (_pkcs11Provider == null) {
                String aPKCS11LibraryFileName = getPkcs11Path();
                String pkcs11ConfigSettings = "name = SmartCard\n" + "library = " + aPKCS11LibraryFileName;

                byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
                ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

                sun.security.pkcs11.SunPKCS11 pkcs11 = new sun.security.pkcs11.SunPKCS11(confStream);
                _pkcs11Provider = (Provider) pkcs11;

                Security.addProvider(_pkcs11Provider);
            }
            return _pkcs11Provider;
        } catch (ProviderException ex) {
            throw new ConfigurationException(eu.europa.ec.markt.dss.ConfigurationException.MSG.NOT_PKCS11_LIB);
        }
    }

    private KeyStore getKeyStore() throws KeyStoreException, ConfigurationException {
        if (_keyStore == null) {
            _keyStore = KeyStore.getInstance("PKCS11", getProvider());
            try {
                _keyStore.load(new KeyStore.LoadStoreParameter() {

                    @Override
                    public ProtectionParameter getProtectionParameter() {
                        return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

                            @Override
                            public void handle(Callback[] callbacks) throws IOException,
                                    UnsupportedCallbackException {
                                for (Callback c : callbacks) {
                                    if (c instanceof PasswordCallback) {
                                        ((PasswordCallback) c).setPassword(callback.getPassword());
                                        return;
                                    }
                                }
                                throw new RuntimeException("No password callback");
                            }
                        });
                    }
                });
            } catch (Exception e) {
                if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
                    if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
                        throw new BadPasswordException(MSG.PKCS11_BAD_PASSWORD);
                    }
                }
                if (e instanceof ConfigurationException) {
                    throw (ConfigurationException) e;
                }
                throw new KeyStoreException("Can't initialize Sun PKCS#11 security " + "provider. Reason: "
                        + e.getCause().getMessage(), e);
            }
        }
        return _keyStore;
    }

    private String getPkcs11Path() {
        return pkcs11Path;
    }

    @Override
    public void close() {
        if (_pkcs11Provider != null) {
            try {
                Security.removeProvider(_pkcs11Provider.getName());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        this._pkcs11Provider = null;
        this._keyStore = null;
    }

    @Override
    public byte[] encryptDigest(byte[] digestValue, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry)
            throws NoSuchAlgorithmException {

        try {
            DigestInfo digestInfo = new DigestInfo(digestAlgo.getAlgorithmIdentifier(), digestValue);
            Cipher cipher = Cipher.getInstance(keyEntry.getSignatureAlgorithm().getPadding());
            cipher.init(Cipher.ENCRYPT_MODE, ((KSPrivateKeyEntry) keyEntry).getPrivateKey());
            return cipher.doFinal(digestInfo.getDEREncoded());
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            // More likely bad password
            throw new BadPasswordException(MSG.PKCS11_BAD_PASSWORD);
        }
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException, ConfigurationException {

        List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

        try {
            KeyStore keyStore = getKeyStore();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, null);
                    list.add(new KSPrivateKeyEntry(entry));
                }
            }

        } catch (Exception e) {
            if (e instanceof ConfigurationException) {
                throw (ConfigurationException) e;
            }
            throw new KeyStoreException("Can't initialize Sun PKCS#11 security " + "provider. Reason: "
                    + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage()), e);
        }

        return list;
    }
}
