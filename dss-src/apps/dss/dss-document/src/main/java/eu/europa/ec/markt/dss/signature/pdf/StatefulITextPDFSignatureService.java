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
package eu.europa.ec.markt.dss.signature.pdf;

import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;
import eu.europa.ec.markt.dss.signature.SignatureParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import com.lowagie.text.DocumentException;

/**
 * Implementation of PDFSignatureService using iText
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */
public class StatefulITextPDFSignatureService implements PDFSignatureService {

    private static final Logger LOG = Logger.getLogger(StatefulITextPDFSignatureService.class.getName());

    private int signatureSize = 15000;

    private byte[] digest;
    private PdfStamper stp;
    private ByteArrayOutputStream out;

    /**
     * @param signatureSize the signatureSize to set
     */
    public void setSignatureSize(int signatureSize) {
        this.signatureSize = signatureSize;
    }

    /**
     * @return the signatureSize
     */
    public int getSignatureSize() {
        return signatureSize;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private PdfStamper prepareStamper(InputStream pdfData, OutputStream output, SignatureParameters parameters)
            throws IOException, DocumentException {

        if(stp != null){
            return stp;
        }

        PdfReader reader = new PdfReader(pdfData);
        stp = PdfStamper.createSignature(reader, output, '\0', null, true);

        PdfSignatureAppearance sap = stp.getSignatureAppearance();
        sap.setAcro6Layers(true);
        sap.setLayer2Text("");
        if(parameters.getSignatureAppearance() != null){
            sap.setRender(PdfSignatureAppearance.SignatureRenderGraphic);
            sap.setImage(null);
            PdfReader stampReader = new PdfReader(parameters.getSignatureAppearance());
            PdfTemplate stamp = stp.getWriter().getImportedPage(stampReader, 1);
            //stamp.setBoundingBox(new Rectangle(200, 100));
            sap.setTemplate(stamp);
            sap.setSignatureGraphic(Image.getInstance(stamp));

            float[] pos = parameters.getSignaturePosition();
            Rectangle rect = new Rectangle(pos[0], pos[1], pos[2], pos[3]);
            sap.setVisibleSignature(rect, 1, parameters.getSignatureName());
        }else{
            sap.setRender(PdfSignatureAppearance.SignatureRenderDescription);
        }

        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("ETSI.CAdES.detached"));
        Calendar cal = Calendar.getInstance();
        cal.setTime(parameters.getSigningDate());
        sap.setSignDate(cal);
        dic.setDate(new PdfDate(cal));

        if(parameters.getReason() != null) {
            dic.setReason(parameters.getReason());
        }
        if(parameters.getLocation() != null) {
            dic.setLocation(parameters.getLocation());
        }
        if(parameters.getContactInfo() != null) {
            dic.setContact(parameters.getContactInfo());
        }

        sap.setCryptoDictionary(dic);

        int csize = getSignatureSize();
        HashMap exc = new HashMap();
        exc.put(PdfName.CONTENTS, new Integer(csize * 2 + 2));

        sap.preClose(exc);

        return stp;
    }

    @Override
    public byte[] digest(InputStream pdfData, SignatureParameters parameters) throws IOException, DocumentException {

        if(digest != null){
            return digest;
        }

        out = new ByteArrayOutputStream();
        PdfStamper stp = prepareStamper(pdfData, out, parameters);

        PdfSignatureAppearance sap = stp.getSignatureAppearance();

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(parameters.getDigestAlgorithm().getName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No " + parameters.getDigestAlgorithm().getName() + " on this JRE!");
        }
        InputStream s = sap.getRangeStream();
        int read = 0;
        byte[] buff = new byte[8192];
        while ((read = s.read(buff, 0, 8192)) > 0) {
            md.update(buff, 0, read);
        }

        digest = md.digest();
        return digest;
    }

    @Override
    public void sign(InputStream pdfData, byte[] signatureValue, OutputStream signedStream,
                     SignatureParameters parameters) throws IOException, DocumentException {

        PdfStamper stp = prepareStamper(pdfData, signedStream, parameters);
        PdfSignatureAppearance sap = stp.getSignatureAppearance();

        byte[] pk = signatureValue;

        int csize = getSignatureSize();
        byte[] outc = new byte[csize];

        PdfDictionary dic2 = new PdfDictionary();

        System.arraycopy(pk, 0, outc, 0, pk.length);

        dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
        sap.close(dic2);

        signedStream.write(out.toByteArray());
        signedStream.close();
    }

    @Override
    public void validateSignatures(InputStream input, SignatureValidationCallback callback) throws IOException,
            SignatureException {
        validateSignatures(input, null, callback, new ArrayList<String>());
    }

    @SuppressWarnings("unchecked")
    private void validateSignatures(InputStream input, PdfDictionary outerCatalog,
                                    SignatureValidationCallback callback, List<String> alreadyLoadedRevisions) throws IOException,
            SignatureException {

        PdfReader reader = new PdfReader(input);
        AcroFields af = reader.getAcroFields();

        /*
         * Search the whole document of a signature
         */
        ArrayList<String> names = af.getSignatureNames();

        LOG.info(names.size() + " signature(s)");
        // For every signature :
        for (String name : names) {

            // Affichage du nom
            LOG.info("Signature name: " + name);
            LOG.info("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            // Affichage sur les revision - version
            LOG.info("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());

            /*
             * We are only interrested in the validation of signature that covers the whole document.
             */
            if (af.signatureCoversWholeDocument(name)) {

                PdfPKCS7 pk = af.verifySignature(name);
                Calendar cal = pk.getSignDate();
                Certificate pkc[] = pk.getCertificates();

                PdfDictionary signatureDictionary = af.getSignatureDictionary(name);
                String revisionName = Integer.toString(af.getRevision(name));
                if (!alreadyLoadedRevisions.contains(revisionName)) {
                    callback.validate(reader, outerCatalog, pk.getSigningCertificate(), cal != null ? cal.getTime() : null, pkc,
                            signatureDictionary, pk);
                    alreadyLoadedRevisions.add(revisionName);
                }

            } else {

                PdfDictionary catalog = reader.getCatalog();

                /*
                 * We open the version of the document that was protected by the signature
                 */
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                InputStream ip = af.extractRevision(name);
                IOUtils.copy(ip, out);
                out.close();
                ip.close();

                /*
                 * You can sign a PDF document with only one signature. So when we want multiple signature, signatures
                 * are appended sequentially to the end of the document. The recursive call help to get the signature
                 * from the original document.
                 */
                validateSignatures(new ByteArrayInputStream(out.toByteArray()), catalog, callback,
                        alreadyLoadedRevisions);

            }
        }

    }
}
