/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/dss/dss-report/src/main/java/eu/europa/ec/markt/dss/report/PdfValidationReportService.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.dss.report;

import eu.europa.ec.markt.dss.validation.report.CertificateVerification;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.SignatureInformation;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelA;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelEPES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelT;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelXL;
import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;
import eu.europa.ec.markt.dss.validation.report.ValidationReport;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.imageio.ImageIO;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfWriter;

/**
 * This service create a PDF report from the validation report of the document.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class PdfValidationReportService {

    private Font defaultFont;

    private Font header1Font;

    private Font header2Font;

    private Font header3Font;

    private Font header4Font;

    private Font monoFont;

    private Image okImage;

    private Image koImage;

    private SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm");

    private enum ParagraphStyle {

        HEADER1, HEADER2, HEADER3, HEADER4, LABEL, VALUE, DEFAULT, CODE

    }

    /**
     * The default constructor for PdfValidationReportService.
     */
    public PdfValidationReportService() {

        try {
            byte[] data = IOUtils.toByteArray(this.getClass().getResourceAsStream("/LiberationSans-Regular.ttf"));
            BaseFont bfo = BaseFont.createFont("LiberationSans-Regular.ttf", BaseFont.WINANSI, BaseFont.EMBEDDED,
                    BaseFont.CACHED, data, null);
            defaultFont = new Font(bfo, 9);

            data = IOUtils.toByteArray(this.getClass().getResourceAsStream("/LiberationSans-Bold.ttf"));
            bfo = BaseFont.createFont("LiberationSans-Bold.ttf", BaseFont.WINANSI, BaseFont.EMBEDDED,
                    BaseFont.CACHED, data, null);
            header1Font = new Font(bfo, 12);
            header1Font.setColor(54, 95, 145);

            data = IOUtils.toByteArray(this.getClass().getResourceAsStream("/LiberationSans-Bold.ttf"));
            bfo = BaseFont.createFont("LiberationSans-Bold.ttf", BaseFont.WINANSI, BaseFont.EMBEDDED,
                    BaseFont.CACHED, data, null);
            header2Font = new Font(bfo, 11);
            header2Font.setColor(79, 129, 189);

            data = IOUtils.toByteArray(this.getClass().getResourceAsStream("/LiberationSans-Bold.ttf"));
            bfo = BaseFont.createFont("LiberationSans-Bold.ttf", BaseFont.WINANSI, BaseFont.EMBEDDED,
                    BaseFont.CACHED, data, null);
            header3Font = new Font(bfo, 9);
            header3Font.setColor(79, 129, 189);

            data = IOUtils.toByteArray(this.getClass().getResourceAsStream("/LiberationSans-BoldItalic.ttf"));
            bfo = BaseFont.createFont("LiberationSans-BoldItalic.ttf", BaseFont.WINANSI, BaseFont.EMBEDDED,
                    BaseFont.CACHED, data, null);
            header4Font = new Font(bfo, 9);
            header4Font.setColor(79, 129, 189);

            data = IOUtils.toByteArray(this.getClass().getResourceAsStream("/LiberationMono-Regular.ttf"));
            bfo = BaseFont.createFont("LiberationMono-Regular.ttf", BaseFont.WINANSI, BaseFont.EMBEDDED,
                    BaseFont.CACHED, data, null);
            monoFont = new Font(bfo, 9);

            BufferedImage img = ImageIO.read(this.getClass().getResourceAsStream("/ok.jpg"));
            okImage = Image.getInstance(img, null);
            okImage.scaleToFit(9, 9);
            okImage.setSpacingAfter(25);
            okImage.setSmask(false);

            img = ImageIO.read(this.getClass().getResourceAsStream("/error.jpg"));
            koImage = Image.getInstance(img, null);
            koImage.scaleToFit(9, 9);
            koImage.setSmask(false);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void createReport(ValidationReport report, OutputStream pdfStream) throws IOException {

        try {
            Document document = new Document();
            PdfWriter writer = PdfWriter.getInstance(document, pdfStream);
            writer.setPdfVersion(PdfWriter.PDF_VERSION_1_4);
            writer.setPDFXConformance(PdfWriter.PDFA1B);
            document.open();

            document.add(p("Time information", ParagraphStyle.HEADER1));
            document.add(p("Verification Time " + report.getTimeInformation().getVerificationTime()));

            int i = 1;
            for (SignatureInformation si : report.getSignatureInformationList()) {
                if (si != null) {
                    writeSignatureInformation(document, si, i++);
                }
            }

            writer.createXmpMetadata();
            document.close();
        } catch (DocumentException e) {
            throw new IOException(e);
        }
    }

    private void writeSignatureInformation(Document document, SignatureInformation si, int index)
            throws DocumentException {

        document.add(p("Signature information " + index, ParagraphStyle.HEADER1));
        document.add(p("Signature verification", si.getSignatureVerification().getSignatureVerificationResult(),
                ParagraphStyle.DEFAULT));
        document.add(p("Signature algorithm : " + si.getSignatureVerification().getSignatureAlgorithm()));

        document.add(p("Certificate Path Revocation Analysis", ParagraphStyle.HEADER2));
        document.add(p("Summary", si.getCertPathRevocationAnalysis().getSummary(), null));

        document.add(p("Certificate Verification", ParagraphStyle.HEADER3));
        for (CertificateVerification cert : si.getCertPathRevocationAnalysis().getCertificatePathVerification()) {
            if (cert != null) {
                writeCertificateVerification(document, cert);
            }
        }

        document.add(p("Trusted List Information", ParagraphStyle.HEADER3));
        document.add(p("Service was found", si.getCertPathRevocationAnalysis().getTrustedListInformation()
                .isServiceWasFound(), null));
        document.add(p("Trusted List well-signed ", si.getCertPathRevocationAnalysis().getTrustedListInformation()
                .isWellSigned(), null));

        document.add(p("Signature level analysis", ParagraphStyle.HEADER2));
        if (si.getSignatureLevelAnalysis() == null) {
            document.add(p("No information available"));
        } else {
            document.add(p("Signature format " + si.getSignatureLevelAnalysis().getSignatureFormat()));

            {
                SignatureLevelBES levelBES = si.getSignatureLevelAnalysis().getLevelBES();

                /* Title level BES */
                document.add(p("Signature Level BES", levelBES.getLevelReached(), ParagraphStyle.HEADER3));

                /* BES : Signing certificate */
                if (levelBES.getSigningCertificate() != null) {
                    document.add(p("Signing certicate: "
                            + levelBES.getSigningCertificate().getSubjectDN().toString()));
                } else {
                    document.add(p("No signing certificate.", ParagraphStyle.DEFAULT));
                }

                if (levelBES.getSigningTime() == null) {
                    document.add(p("No signing time attribute.", ParagraphStyle.DEFAULT));
                } else {
                    document.add(p("Signing time : " + levelBES.getSigningTime()));
                }

                /* BES : List of certificates */
                document.add(p("Certificates", ParagraphStyle.HEADER4));
                if (levelBES.getCertificates() != null && levelBES.getCertificates().size() > 0) {
                    document.add(p("There is " + levelBES.getCertificates().size() + " in the signature."));
                    for (X509Certificate c : levelBES.getCertificates()) {
                        writeCertificate(document, c);
                    }
                } else {
                    document.add(p("No certificate in the signature.", ParagraphStyle.DEFAULT));
                }
            }

            {
                SignatureLevelEPES levelEPES = si.getSignatureLevelAnalysis().getLevelEPES();
                document.add(p("Signature Level EPES ", levelEPES.getLevelReached(), ParagraphStyle.HEADER3));
                if (levelEPES.getPolicyId() == null) {
                    document.add(p("No policy information"));
                } else {
                    document.add(p("Signature policy" + levelEPES.getPolicyId().getPolicy()));
                }
            }

            {
                SignatureLevelT levelT = si.getSignatureLevelAnalysis().getLevelT();
                document.add(p("Signature Level T", levelT.getLevelReached(), ParagraphStyle.HEADER3));
                if (levelT.getSignatureTimestampVerification() == null
                        || levelT.getSignatureTimestampVerification().size() == 0) {
                    document.add(p("No Timestamp in the document"));
                } else {
                    document.add(p("There is " + levelT.getSignatureTimestampVerification().size()
                            + " timestamp(s) in the document"));
                    for (int i = 0; i < levelT.getSignatureTimestampVerification().size(); i++) {
                        TimestampVerificationResult ts = levelT.getSignatureTimestampVerification().get(i);
                        writeTimestampResultInformation(document, ts, "Timestamp " + (i + 1));
                    }
                }
            }

            {
                SignatureLevelC levelC = si.getSignatureLevelAnalysis().getLevelC();
                if (levelC != null) {
                    document.add(p("Signature Level C", levelC.getLevelReached(), ParagraphStyle.HEADER3));

                    if (levelC.getCertificateRefsVerification().isValid()) {
                        document.add(p("All the certificate references needed are in the signature"));
                    } else {
                        document.add(p("Some required certificate references are not in the signature"));
                    }

                    if (levelC.getRevocationRefsVerification().isValid()) {
                        document.add(p("All the revocation information references needed are in the signature"));
                    } else {
                        document.add(p("Some required revocation information references are not in the signature"));
                    }
                }
            }

            {
                SignatureLevelX levelX = si.getSignatureLevelAnalysis().getLevelX();
                if (levelX != null) {
                    document.add(p("Signature Level X", levelX.getLevelReached(), ParagraphStyle.HEADER3));

                    int x1Count = levelX.getSignatureAndRefsTimestampsVerification() == null ? 0 : levelX
                            .getSignatureAndRefsTimestampsVerification().length;
                    int x2Count = levelX.getReferencesTimestampsVerification() == null ? 0 : levelX
                            .getReferencesTimestampsVerification().length;

                    document.add(p("There is " + (x1Count + x2Count) + " X-Timestamp(s) in the document"));

                    /* Signature and ref */
                    if (x1Count > 0) {
                        for (int i = 0; i < x1Count; i++) {
                            TimestampVerificationResult ts = levelX.getSignatureAndRefsTimestampsVerification()[i];
                            writeTimestampResultInformation(document, ts, "X1-Timestamp " + (i + 1));
                        }
                    }

                    /* Signature and ref */
                    if (x2Count > 0) {
                        for (int i = 0; i < x2Count; i++) {
                            TimestampVerificationResult ts = levelX.getReferencesTimestampsVerification()[i];
                            writeTimestampResultInformation(document, ts, "X2-Timestamp " + (i + 1));
                        }
                    }
                }
            }

            {
                SignatureLevelXL levelXL = si.getSignatureLevelAnalysis().getLevelXL();
                if (levelXL != null) {
                    document.add(p("Signature Level XL", levelXL.getLevelReached(), ParagraphStyle.HEADER3));

                    if (levelXL.getCertificateValuesVerification().isValid()) {
                        document.add(p("All the certificates needed are in the signature"));
                    } else {
                        document.add(p("Some required certificates are not in the signature"));
                    }

                    if (levelXL.getRevocationValuesVerification().isValid()) {
                        document.add(p("All the revocation information needed are in the signature"));
                    } else {
                        document.add(p("Some required revocation information are not in the signature"));
                    }
                }
            }

            {
                SignatureLevelA levelA = si.getSignatureLevelAnalysis().getLevelA();
                if (levelA != null) {
                    document.add(p("Signature Level A", levelA.getLevelReached(), ParagraphStyle.HEADER3));

                    if (levelA.getArchiveTimestampsVerification() == null
                            || levelA.getArchiveTimestampsVerification().size() == 0) {
                        document.add(p("No Timestamp in the document"));
                    } else {
                        document.add(p("There is " + levelA.getArchiveTimestampsVerification().size()
                                + " A-timestamp(s) in the document"));
                        for (int i = 0; i < levelA.getArchiveTimestampsVerification().size(); i++) {
                            TimestampVerificationResult ts = levelA.getArchiveTimestampsVerification().get(i);
                            writeTimestampResultInformation(document, ts, "A-Timestamp " + (i + 1));
                        }
                    }
                }
            }

        }

        document.add(p("Qualification Verification", ParagraphStyle.HEADER2));
        if (si.getCertPathRevocationAnalysis() == null) {
            document.add(p("No qualification verification can be retrived !"));
        } else {
            document.add(p("QCWithSSCD", si.getQualificationsVerification().getQCWithSSCD(), null));
            document.add(p("QCNoSSCD", si.getQualificationsVerification().getQCNoSSCD(), null));
            document.add(p("QCSSCDStatusAsInCert", si.getQualificationsVerification().getQCSSCDStatusAsInCert(),
                    null));
            document.add(p("QCForLegalPerson", si.getQualificationsVerification().getQCForLegalPerson(), null));
        }

        document.add(p("QC Statement Information", ParagraphStyle.HEADER2));
        if (si.getQcStatementInformation() == null) {
            document.add(p("No QC Statement Information available"));
        } else {
            document.add(p("QCP presence", si.getQcStatementInformation().getQCPPresent(), null));
            document.add(p("QCP+ presence", si.getQcStatementInformation().getQCPPlusPresent(), null));
            document.add(p("QcCompliance presence", si.getQcStatementInformation().getQcCompliancePresent(), null));
            document.add(p("QcSSCD presence", si.getQcStatementInformation().getQcSCCDPresent(), null));
        }

        document.add(p("Final Conclusion", ParagraphStyle.HEADER2));
        document.add(p("The signature is " + si.getFinalConclusion()));
    }

    private void writeTimestampResultInformation(Document document, TimestampVerificationResult ts, String title)
            throws DocumentException {
        document.add(p(title, ParagraphStyle.HEADER4));
        document.add(p("Issuer name: " + ts.getIssuerName()));
        document.add(p("Serial number: " + ts.getSerialNumber()));
        document.add(p("Signature algorithm: " + ts.getSignatureAlgorithm()));
        document.add(p("Signature verification", ts.getSameDigest(), ParagraphStyle.DEFAULT));
        document.add(p("Creation time: " + sdf.format(ts.getCreationTime())));
    }

    private void writeCertificate(Document document, X509Certificate cert) throws DocumentException {
        document.add(p("Certificate of " + cert.getSubjectX500Principal().toString(), ParagraphStyle.HEADER4));
        document.add(p("Version: " + cert.getVersion()));
        document.add(p("Subject: " + cert.getSubjectX500Principal().toString()));
        document.add(p("Issuer: " + cert.getIssuerX500Principal().toString()));

        try {
            StringWriter writer = new StringWriter();
            PEMWriter out = new PEMWriter(writer);
            out.writeObject(cert);
            out.close();

            document.add(p(writer.toString(), ParagraphStyle.CODE));
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void writeCertificateVerification(Document document, CertificateVerification cert)
            throws DocumentException {
        document.add(p(cert.getCertificate().getSubjectDN().toString(), ParagraphStyle.HEADER4));
        document.add(p("Issuer name : " + cert.getCertificate().getIssuerDN()));
        document.add(p("Serial Number : " + cert.getCertificate().getSerialNumber()));
        document.add(p("Validity at signing time : " + cert.getValidityPeriodVerification()));
        document.add(p("Certificate status " + cert.getCertificateStatus().getStatus()));
    }

    private Paragraph p(String s) {
        return p(s, ParagraphStyle.DEFAULT);
    }

    private Paragraph p(String s, ParagraphStyle style) {
        return p(null, s, style);
    }

    private Paragraph p(String s, Result r, ParagraphStyle style) {
        return p(r.isValid() ? okImage : koImage, s, style);
    }

    private Paragraph p(String s, boolean r, ParagraphStyle style) {
        return p(r ? okImage : koImage, s, style);
    }

    private Paragraph p(Image img, String s, ParagraphStyle style) {

        Paragraph p = new Paragraph("", defaultFont);
        Font font = null;

        if (style == null) {
            style = ParagraphStyle.DEFAULT;
        }
        switch (style) {
        case HEADER1:
            font = header1Font;
            p.setSpacingBefore(20);
            break;
        case HEADER2:
            font = header2Font;
            p.setSpacingBefore(8);
            break;
        case HEADER3:
            font = header3Font;
            p.setSpacingBefore(8);
            break;
        case HEADER4:
            font = header4Font;
            p.setSpacingBefore(8);
            break;
        case CODE:
            font = monoFont;
            p.setSpacingBefore(8);
            break;
        default:
            font = defaultFont;
            break;
        }

        if (img != null) {
            p.add(new Chunk(img, 0, -1));
        }

        p.add(new Chunk(s, font));

        return p;

    }

}
