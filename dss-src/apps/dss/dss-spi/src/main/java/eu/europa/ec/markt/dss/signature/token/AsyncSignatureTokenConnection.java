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

import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * Sometimes, the signature process has to be split in two phases : the digest phase and the encryption phase. This
 * separation is useful when the file and the SSCD are not on the same hardware. Two implementation of
 * AsyncSignatureTokenConnection are provided. Only MSCAPI requires the signature to be done in one step (MS CAPI don't
 * provide any RSA encryption operations).
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public abstract class AsyncSignatureTokenConnection implements SignatureTokenConnection {

    /**
     * The encryption of a digest it the atomic operation done by the SSCD. This encryption (RSA, DSA, ...) create the
     * signature value.
     * 
     * @param digestValue
     * @param digestAlgo
     * @param keyEntry
     * @return
     */
    abstract public byte[] encryptDigest(byte[] digestValue, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry)
            throws NoSuchAlgorithmException;

    /**
     * The encryption of a digest it the atomic operation done by the SSCD. This encryption (RSA, DSA, ...) create the
     * signature value.
     * 
     * @param digest
     * @param keyEntry
     * @return
     * @throws NoSuchAlgorithmException
     */
    public byte[] encryptDigest(Digest digest, DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException {
        return this.encryptDigest(digest.getValue(), digest.getAlgorithm(), keyEntry);
    }

    @Override
    public byte[] sign(InputStream stream, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry)
            throws NoSuchAlgorithmException, IOException {

        if (SignatureAlgorithm.RSA == keyEntry.getSignatureAlgorithm()) {
            MessageDigest digester = MessageDigest.getInstance(digestAlgo.getName());
            byte[] buffer = new byte[4096];
            int count = 0;
            while ((count = stream.read(buffer)) > 0) {
                digester.update(buffer, 0, count);
            }
            byte[] digestValue = digester.digest();
            return encryptDigest(digestValue, digestAlgo, keyEntry);
        } else {
            Signature signature = Signature.getInstance(keyEntry.getSignatureAlgorithm().getJavaSignatureAlgorithm(
                    digestAlgo)) ;
            try {
                signature.initSign(((KSPrivateKeyEntry) keyEntry).getPrivateKey());
                byte[] buffer = new byte[4096];
                int count = 0;
                while ((count = stream.read(buffer)) > 0) {
                    signature.update(buffer, 0, count);
                }
                byte[] signValue = signature.sign();
                return signValue;
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
    }

}