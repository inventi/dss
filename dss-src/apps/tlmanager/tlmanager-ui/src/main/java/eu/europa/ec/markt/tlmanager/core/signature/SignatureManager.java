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

package eu.europa.ec.markt.tlmanager.core.signature;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.common.JavaPreferencesDAO;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.dss.common.UserPreferencesDAO;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.token.RFC3370Pkcs11SignatureToken;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.MSCAPISignatureToken;
import eu.europa.ec.markt.dss.signature.token.PasswordInputCallback;
import eu.europa.ec.markt.dss.signature.token.RFC3370Pkcs12SignatureToken;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.tlmanager.core.exception.SignatureException;
import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger;
import eu.europa.ec.markt.tlmanager.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;

/**
 * SignatureManager deals with everything related to the creation of a signature for a given tsl.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignatureManager {
    private static final Logger LOG = Logger.getLogger(SignatureManager.class.getName());

    private UserPreferencesDAO userPreferencesDAO = new JavaPreferencesDAO();
    private static final SignatureFormat SIGNATURE_FORMAT = SignatureFormat.XAdES_BES;
    private static final SignatureAlgorithm SIGNATURE_ALGO = SignatureAlgorithm.RSA;
    private static final DigestAlgorithm SIGNATURE_DIGEST = DigestAlgorithm.SHA1;

    private ValidationLogger validationLogger;
    private InMemoryDocument document;
    private SignatureTokenConnection signatureTokenConnection;
    private XAdESService xadesService;
    private SignatureTokenType provider = SignatureTokenType.PKCS11;
    private SignatureTokenType lastProvider;
    private File pkcs11Library;
    private File pkcs12File;

    private File target;
    private char[] password;
    private PasswordInputCallback pwCallback;

    private List<DSSPrivateKeyEntry> keys;
    private Certificate selectedCertificate;

    /**
     * The default constructor for SignatureManager.
     * 
     * @param validationLogger the <code>ValidationLogger</code> object
     */
    public SignatureManager(ValidationLogger validationLogger) {
        this.validationLogger = validationLogger;

        xadesService = new XAdESService();
    }

    /**
     * Initialises the <code>InMemoryDocument</code> from a provided <code>Document</code>.
     */
    public void initInMemoryDocument(org.w3c.dom.Document document) {
        if (document == null) {
            LOG.log(Level.SEVERE, ">>> Document is null!");
        }
        try {
            ByteArrayOutputStream outputDoc = new ByteArrayOutputStream();
            Result output = new StreamResult(outputDoc);
            Transformer transformer = Util.createPrettyTransformer(3);
            Source source = new DOMSource(document);
            transformer.transform(source, output);
            this.document = new InMemoryDocument(outputDoc.toByteArray());

            outputDoc.close();
        } catch (TransformerConfigurationException tce) {
            LOG.log(Level.SEVERE, ">>>" + tce.getMessage());
        } catch (TransformerFactoryConfigurationError tfce) {
            LOG.log(Level.SEVERE, ">>>" + tfce.getMessage());
        } catch (TransformerException te) {
            LOG.log(Level.SEVERE, ">>>" + te.getMessage());
        } catch (IOException ioe) {
            LOG.log(Level.SEVERE, ">>>" + ioe.getMessage());
        }
    }

    private void initializeTokenCon(SignatureTokenType provider) {
        if (signatureTokenConnection != null) {
            signatureTokenConnection.close();
            selectedCertificate = null;
        }
        if (SignatureTokenType.PKCS11.equals(provider)) {
            signatureTokenConnection = new RFC3370Pkcs11SignatureToken(pkcs11Library.getAbsolutePath(), pwCallback);
            lastProvider = SignatureTokenType.PKCS11;
        } else if (SignatureTokenType.PKCS12.equals(provider)) {
            signatureTokenConnection = new RFC3370Pkcs12SignatureToken(password, pkcs12File);
            lastProvider = SignatureTokenType.PKCS12;
        } else if (SignatureTokenType.MSCAPI.equals(provider)) {
            signatureTokenConnection = new MSCAPISignatureToken();
            lastProvider = SignatureTokenType.MSCAPI;
        }
    }

    /**
     * Retrieves the certificate from the respective source.
     * 
     * @throws SignatureException
     */
    public void retrieveCertificates() throws SignatureException {
        if (provider == null) {
            return;
        }
        if (signatureTokenConnection == null || !provider.equals(lastProvider)) { // provider was changed in ui
            initializeTokenCon(provider);
        }
        try {
            keys = signatureTokenConnection.getKeys();
        } catch (KeyStoreException kse) {
            signatureTokenConnection = null; // make sure that it is reinitialised next time!
            String msg = kse.getMessage();
            LOG.log(Level.SEVERE, ">>>Unable to get Keys: " + msg);
            throw new SignatureException(msg, kse);
        }
    }

    /**
     * Returns the matching source for the currently selected provider
     * 
     * @return the matching source file
     */
    public File getMatchingSource() {
        if (provider.equals(SignatureTokenType.PKCS11)) {
            return getPkcs11Library();
        } else if (provider.equals(SignatureTokenType.PKCS12)) {
            return getPkcs12File();
        }

        return null;
    }

    /**
     * @param provider the signature token provider
     */
    public void setProvider(SignatureTokenType provider) {
        if (provider != null) {
            userPreferencesDAO.setSignatureTokenType(provider);
        }
        this.provider = provider;
    }

    /**
     * @return the tokenType
     */
    public SignatureTokenType getProvider() {
        if (provider == null) {
            provider = userPreferencesDAO.getSignatureTokenType();
        }
        return provider;
    }

    /**
     * Gets the pkcs11 library.
     * 
     * @return the pkcs11 library.
     */
    public File getPkcs11Library() {
        if (pkcs11Library == null) {
            String pkcs11LibraryPath = userPreferencesDAO.getPKCS11LibraryPath();
            if (pkcs11LibraryPath != null && !pkcs11LibraryPath.isEmpty()) {
                pkcs11Library = new File(pkcs11LibraryPath);
            }
        }
        return pkcs11Library;
    }

    /**
     * Sets the pkcs11 library.
     * 
     * @param pkcs11LibraryPath the file
     */
    public void setPkcs11Library(File pkcs11LibraryPath) {
        if (pkcs11LibraryPath != null) {
            userPreferencesDAO.setPKCS11LibraryPath(pkcs11LibraryPath.getAbsolutePath());
        }
        this.pkcs11Library = pkcs11LibraryPath;
    }

    /**
     * Gets the pkcs12 library.
     * 
     * @return the pkcs12 library
     */
    public File getPkcs12File() {
        if (pkcs12File == null) {
            String pkcs12FilePath = userPreferencesDAO.getPKCS12FilePath();
            if (pkcs12FilePath != null && !pkcs12FilePath.isEmpty()) {
                pkcs12File = new File(pkcs12FilePath);
            }
        }
        return pkcs12File;
    }

    /**
     * Sets the pkcs12 library.
     * 
     * @param pkcs12FilePath the file
     */
    public void setPkcs12File(File pkcs12FilePath) {
        if (pkcs12FilePath != null) {
            userPreferencesDAO.setPKCS12FilePath(pkcs12FilePath.getAbsolutePath());
        }
        this.pkcs12File = pkcs12FilePath;
    }

    /**
     * Retrieves the validation message that will be displayed in the ui.
     * 
     * @return the list
     */
    public List<ValidationLogger.Message> retrieveValidationMessages() {
        return validationLogger.getValidationMessages();
    }

    /**
     * Checks if the validation logger has any errors.
     * 
     * @return true, if the validation contains errors
     */
    public boolean isValidationErroneous() {
        return validationLogger.hasErrors();
    }

    /**
     * Do the actual signing.
     * 
     * @throws IOException
     */
    public void sign() throws IOException {
        SignatureParameters parameters = new SignatureParameters();
        parameters.setSigningDate(new Date());
        DSSPrivateKeyEntry pk = determineCurrentPK();
        parameters.setSigningCertificate((X509Certificate) pk.getCertificate());
        parameters.setCertificateChain(Arrays.asList((X509Certificate[]) pk.getCertificateChain()));

        parameters.setSignatureFormat(SIGNATURE_FORMAT);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

        parameters.setClaimedSignerRole(null);

        parameters.setSignaturePolicyId(null);

        InputStream toBeSigned = xadesService.toBeSigned(document, parameters);

        byte[] signatureValue;
        try {
            signatureValue = signatureTokenConnection.sign(toBeSigned, SIGNATURE_DIGEST, pk);
            Document signedDocument = xadesService.signDocument(document, parameters, signatureValue);

            FileOutputStream output = new FileOutputStream(target);
            IOUtils.copy(signedDocument.openStream(), output);
            output.close();
        } catch (NoSuchAlgorithmException nsae) {
            LOG.log(Level.SEVERE, "No suited algorithm found for " + SIGNATURE_ALGO + " with " + SIGNATURE_DIGEST
                    + ": " + nsae.getMessage());
        }
    }

    /**
     * Extract the list of <code>Certificate</code> from the current list of <code>PrivateKeyEntry</code>
     * 
     * @return a list of certificates
     */
    public List<Certificate> getCertificates() throws SignatureException {
        if (keys == null || !provider.equals(lastProvider)) {
            retrieveCertificates();
        }
        List<Certificate> certificates = new ArrayList<Certificate>();
        for (DSSPrivateKeyEntry key : keys) {
            certificates.add(key.getCertificate());
        }

        return certificates;
    }

    private DSSPrivateKeyEntry determineCurrentPK() {
        DSSPrivateKeyEntry pk = null;
        if (keys != null && selectedCertificate != null) {
            for (DSSPrivateKeyEntry key : keys) {
                if (selectedCertificate.equals(key.getCertificate())) {
                    pk = key;
                    break;
                }
            }
        }

        return pk;
    }

    /**
     * Sets the password.
     * 
     * @param password the new password
     */
    public void setPassword(char[] password) {
        this.password = password;
    }

    /**
     * @return the password
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * @param pwCallback the pwCallback to set
     */
    public void setPwCallback(PasswordInputCallback pwCallback) {
        this.pwCallback = pwCallback;
    }

    /**
     * @return the selectedCertificate
     */
    public Certificate getSelectedCertificate() {
        return selectedCertificate;
    }

    /**
     * @param selectedCertificate the selectedCertificate to set
     */
    public void setSelectedCertificate(Certificate selectedCertificate) {
        this.selectedCertificate = selectedCertificate;
    }

    /**
     * @return the document
     */
    public InMemoryDocument getDocument() {
        return document;
    }

    /**
     * @param document the document to set
     */
    public void setDocument(InMemoryDocument document) {
        this.document = document;
    }

    /**
     * @return the target
     */
    public File getTarget() {
        return target;
    }

    /**
     * @param target the target to set
     */
    public void setTarget(File target) {
        if (!target.isDirectory()) {
            this.target = target;
        }
    }

    /**
     * Returns true, if any source is set
     * 
     * @return true, if any source is set
     */
    public boolean isAnySource() {
        if (pkcs11Library == null && pkcs12File == null) {
            return false;
        }

        return true;
    }
}