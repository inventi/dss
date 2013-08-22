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

package eu.europa.ec.markt.dss.applet;

import eu.europa.ec.markt.dss.ConfigurationException;
import eu.europa.ec.markt.dss.applet.model.SignatureWizardModel;
import eu.europa.ec.markt.dss.applet.wizard.AbstractWizardPanel;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;

import java.awt.Component;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

/**
 * Displays a list of certificate available in the choosed SignatureToken. The use must choose one of them.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class ChooseCertificatePanel extends AbstractWizardPanel {

    private static final Logger LOG = Logger.getLogger(ChooseCertificatePanel.class.getName());

    public static final String ID = "CHOOSE_KEY";
    private SignatureWizardModel model;
    private SignatureTokenConnection connection;

    class CertificateListModel extends DefaultListModel {

        List<DSSPrivateKeyEntry> entries = new ArrayList<DSSPrivateKeyEntry>();

        public void refresh() throws KeyStoreException, ConfigurationException {
            entries = connection.getKeys();

            this.removeAllElements();
            for (DSSPrivateKeyEntry entry : entries) {
                this.addElement(entry);
            }
        }

    }

    private CertificateListModel listModel = new CertificateListModel();

    @Override
    public Object getPanelDescriptorIdentifier() {
        return ID;
    }

    /** Creates new form ChooseCertificatePanel */
    public ChooseCertificatePanel(SignatureWizardModel signatureModel) {
        this.model = signatureModel;
        initComponents();

        certificateList.setCellRenderer(new DefaultListCellRenderer() {

            public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected,
                    boolean cellHasFocus) {
                X509Certificate cert = (X509Certificate) ((DSSPrivateKeyEntry) value).getCertificate();
                String subjectDN = cert.getSubjectDN().getName();
                int dnStartIndex = subjectDN.indexOf("CN=") + 3;
                if (dnStartIndex > 0 && subjectDN.indexOf(",", dnStartIndex) > 0) {
                    subjectDN = subjectDN.substring(dnStartIndex, subjectDN.indexOf(",", dnStartIndex)) + " (SN:"
                            + cert.getSerialNumber() + ")";
                }
                return super.getListCellRendererComponent(list, subjectDN, index, isSelected, cellHasFocus);
            }
        });

        certificateList.addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (certificateList.getSelectedValue() != null) {
                    model.setPrivateKey((DSSPrivateKeyEntry) certificateList.getSelectedValue());
                    getWizard().setNextFinishButtonEnabled(true);
                }
            }
        });

    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        certificateList = new javax.swing.JList();
        refreshButton = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        setBackground(new java.awt.Color(255, 255, 255));

        jScrollPane1.setName("certificates_scroll"); // NOI18N

        certificateList.setModel(listModel);
        certificateList.setName("certificates"); // NOI18N
        jScrollPane1.setViewportView(certificateList);

        refreshButton.setIcon(new javax.swing.ImageIcon(getClass().getResource(
                "/eu/europa/ec/markt/dss/applet/wizard/refresh.png"))); // NOI18N
        refreshButton.setMnemonic(java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n")
                .getString("REFRESH").charAt(0));
        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n"); // NOI18N
        refreshButton.setText(bundle.getString("REFRESH")); // NOI18N
        refreshButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshButtonActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 11));
        jLabel1.setText(bundle.getString("CHOOSE_SIGNING_CERTIFICATE")); // NOI18N

        jLabel2.setText(bundle.getString("CERTIFICATE_LIST_REFRESH")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 380,
                                                Short.MAX_VALUE)
                                        .addComponent(jLabel1)
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addComponent(jLabel2)
                                                        .addPreferredGap(
                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                        .addComponent(refreshButton))).addContainerGap()));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 193, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jLabel2).addComponent(refreshButton)).addContainerGap()));
    }// </editor-fold>//GEN-END:initComponents

    private void refreshButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_refreshButtonActionPerformed
        try {
            listModel.refresh();
        } catch (KeyStoreException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
    }// GEN-LAST:event_refreshButtonActionPerformed

    @Override
    public Object getNextPanelDescriptor() {
        if (model.getPrivateKey() == null) {
            return null;
        } else {
            return PersonalDataPanel.ID;
        }
    }

    @Override
    public Object getBackPanelDescriptor() {
        return SignatureTokenAPIPanel.ID;
    }

    @Override
    public void aboutToDisplayPanel() {
        getWizard().setStepsProgression(5);
        try {
            connection = model.createTokenConnection(getWizard());
            listModel.refresh();
            model.setPrivateKey(null);
        } catch (KeyStoreException ex) {
            Logger.getLogger(ChooseCertificatePanel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JList certificateList;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton refreshButton;
    // End of variables declaration//GEN-END:variables
}
