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
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * Class holding all PKCS#12 file access logic.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class Pkcs12SignatureToken extends AsyncSignatureTokenConnection {

    private char[] password;

    private File pkcs12File;

    /**
     * Create a SignatureTokenConnection with the provided password and path to PKCS#12 file. The default constructor
     * for Pkcs12SignatureToken.
     * 
     * @param password
     * @param pkcs12FilePath
     */
    public Pkcs12SignatureToken(String password, String pkcs12FilePath) {
        this(password.toCharArray(), new File(pkcs12FilePath));
    }

    /**
     * Create a SignatureTokenConnection with the provided password and path to PKCS#12 file. The default constructor
     * for Pkcs12SignatureToken.
     * 
     * @param password
     * @param pkcs12FilePath
     */
    public Pkcs12SignatureToken(char[] password, String pkcs12FilePath) {
        this(password, new File(pkcs12FilePath));
    }

    /**
     * Create a SignatureTokenConnection with the provided password and path to PKCS#12 file. The default constructor
     * for Pkcs12SignatureToken.
     * 
     * @param password
     * @param pkcs12FilePath
     */
    public Pkcs12SignatureToken(String password, File pkcs12File) {
        this(password.toCharArray(), pkcs12File);
    }

    /**
     * Create a SignatureTokenConnection with the provided password and path to PKCS#12 file. The default constructor
     * for Pkcs12SignatureToken.
     * 
     * @param password
     * @param pkcs12FilePath
     */
    public Pkcs12SignatureToken(char[] password, File pkcs12File) {
        this.password = password;
        if (!pkcs12File.exists()) {
            throw new RuntimeException("File Not Found " + pkcs12File.getAbsolutePath());
        }
        this.pkcs12File = pkcs12File;
    }

    @Override
    public void close() {
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
            // More likely the password is not good.
            throw new BadPasswordException(MSG.PKCS12_BAD_PASSWORD);
        }

    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException {

        List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream input = new FileInputStream(pkcs12File);
            keyStore.load(input, password);
            input.close();

            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias,
                            new KeyStore.PasswordProtection(password));
                    list.add(new KSPrivateKeyEntry(entry));
                }
            }

        } catch (IOException e) {
            if (e.getCause() instanceof BadPaddingException) {
                throw new BadPasswordException(MSG.PKCS12_BAD_PASSWORD);
            }
            throw new KeyStoreException("Can't initialize Sun PKCS#12 security " + "provider. Reason: "
                    + e.getCause().getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException("Can't initialize Sun PKCS#12 security " + "provider. Reason: "
                    + e.getCause().getMessage(), e);
        } catch (CertificateException e) {
            throw new KeyStoreException("Can't initialize Sun PKCS#12 security " + "provider. Reason: "
                    + e.getCause().getMessage(), e);
        } catch (UnrecoverableEntryException e) {
            throw new KeyStoreException("Can't initialize Sun PKCS#12 security " + "provider. Reason: "
                    + e.getCause().getMessage(), e);
        }
        return list;
    }
}
