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

import eu.europa.ec.markt.dss.applet.model.SignatureWizardModel;
import eu.europa.ec.markt.dss.applet.model.WizardUsage;
import eu.europa.ec.markt.dss.applet.wizard.AbstractWizardPanel;
import eu.europa.ec.markt.dss.signature.FileDocument;

import javax.swing.JFileChooser;

/**
 * 
 * Let the user choose a file to sign.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SelectDocumentForSignaturePanel extends AbstractWizardPanel {

    public static final String ID = "CHOOSE_FILE_TO_SIGN";

    private SignatureWizardModel model;

    private JFileChooser jFileChooser1;

    /** Creates new form SelectDocumentPanel */
    public SelectDocumentForSignaturePanel(SignatureWizardModel signatureModel) {

        this.model = signatureModel;

        initComponents();

        jFileChooser1 = new JFileChooser();
    }

    @Override
    public Object getPanelDescriptorIdentifier() {
        return ID;
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        filename = new javax.swing.JTextField();

        setBackground(new java.awt.Color(255, 255, 255));

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 11));
        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n"); // NOI18N
        jLabel1.setText(bundle.getString("FILE_TO_SIGN")); // NOI18N

        jButton1.setMnemonic(java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n").getString("BROWSE").charAt(0));
        jButton1.setText(bundle.getString("BROWSE")); // NOI18N
        jButton1.setName("browse"); // NOI18N
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        filename.setEditable(false);
        filename.setText(bundle.getString("NO_FILE_SELECTED")); // NOI18N
        filename.setBorder(null);
        filename.setName("file_path"); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButton1)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(filename, javax.swing.GroupLayout.DEFAULT_SIZE, 355, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(filename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton1)
                .addContainerGap(265, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton1ActionPerformed

        int result = jFileChooser1.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            model.setOriginalFile(new FileDocument(jFileChooser1.getSelectedFile()));
            filename.setText(model.getOriginalFile().getName());
            getWizard().setNextFinishButtonEnabled(true);
        }

    }// GEN-LAST:event_jButton1ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField filename;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    // End of variables declaration//GEN-END:variables

    @Override
    public Object getNextPanelDescriptor() {
        if (model.getOriginalFile() != null) {
            return ChooseSignaturePanel.ID;
        } else {
            return null;
        }
    }

    @Override
    public Object getBackPanelDescriptor() {
        if (model.isUsageParameterFound()) {
            return null;
        } else {
            return ActivityPanel.ID;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.wizard.AbstractWizardPanel#aboutToDisplayPanel()
     */
    @Override
    public void aboutToDisplayPanel() {
        if (model.getWizardUsage() == WizardUsage.SIGN) {
            getWizard().setStepsProgression(new WizardStepsSign());
            getWizard().setStepsProgression(1);
        }
        if(model.getOriginalFile() == null) {
            getWizard().setNextFinishButtonEnabled(false);
        }
    }

}