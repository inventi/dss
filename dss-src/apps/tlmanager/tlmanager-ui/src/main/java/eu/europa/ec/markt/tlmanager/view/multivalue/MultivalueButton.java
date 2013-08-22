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

package eu.europa.ec.markt.tlmanager.view.multivalue;

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.view.common.ContentDialog;

import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ResourceBundle;
import java.util.logging.Logger;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

/**
 * A button for the multivalue component.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class MultivalueButton extends JPanel implements ContentWatcher {

    private static final Logger LOGGER = Logger.getLogger(MultivalueButton.class.getName());

    private static final ResourceBundle uiKeys = ResourceBundle.getBundle(
            "eu/europa/ec/markt/tlmanager/uiKeysComponents", Configuration.getInstance().getLocale());
    private static String LABEL_LING = uiKeys.getString("MultivalueButton.title.lingual");
    private static String LABEL_MVAL = uiKeys.getString("MultivalueButton.title.multiple");
    private int buttonHSize = 120;
    private MandatoryLabelHandler labelHandler;

    /**
     * Instantiates a new multivalue button.
     * 
     * @param multiMode the multi mode
     * @param mandatoryValue the mandatory value
     * @param multiConfValues the multi conf values
     */
    public MultivalueButton(MultiMode multiMode, String mandatoryValue, String[] multiConfValues) {
        this();
        switch (multiMode) {
        case LING_NORMAL:
        case LING_POSTAL:
            initValueButton(LABEL_LING, null);
            break;
        case MULTI_FIX:
        case MULTI_FREE:
        case MULTI_ANYURI:
        case MULTI_ASI:
        case MULTI_TSPINEX:
        case DIGITAL_ID:
            initValueButton(LABEL_MVAL, null);
            break;
        default:
            LOGGER.severe("Unrecognized mode : " + multiMode);
        }
        multivaluePanel = new MultivaluePanel(multiMode, mandatoryValue, multiConfValues);
        multivaluePanel.addContentWatcher(this);
    }

    /**
     * Instantiates a new multivalue button. Could be private, but netbeans wants a no attribute constructor...
     */
    public MultivalueButton() {
        int multi = 8; // just a rough number to take the size of a character into account
        buttonHSize = LABEL_LING.length() * multi;
        if (LABEL_LING.length() < LABEL_MVAL.length()) {
            buttonHSize = LABEL_MVAL.length() * multi; // set to the larger
        }

        initComponents();
    }

    private void initValueButton(final String label, final Frame container) {
        valueButton.setText(label);

        valueButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (dialog == null) {
                    dialog = new ContentDialog(container, label, true);
                    dialog.setSize(666, 280);
                    dialog.getContentPane().setLayout(new BorderLayout());
                    dialog.getContentPane().add(multivaluePanel, BorderLayout.CENTER);
                    dialog.setDialogContent(multivaluePanel);
                }

                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        multivaluePanel.refresh();
                    }
                });
                dialog.setVisible(true);
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

        valueButton = new javax.swing.JButton();
        previewLabel = new javax.swing.JLabel();

        setPreferredSize(new java.awt.Dimension(266, 26));

        valueButton.setText("Multiple Values");
        valueButton.setMaximumSize(new java.awt.Dimension(buttonHSize, 23));
        valueButton.setMinimumSize(new java.awt.Dimension(buttonHSize, 23));
        valueButton.setPreferredSize(new java.awt.Dimension(buttonHSize, 23));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addComponent(valueButton, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(previewLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 167, Short.MAX_VALUE)
                        .addContainerGap()));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(valueButton, javax.swing.GroupLayout.DEFAULT_SIZE, 26, Short.MAX_VALUE)
                .addComponent(previewLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 26, Short.MAX_VALUE));
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel previewLabel;
    private javax.swing.JButton valueButton;
    // End of variables declaration//GEN-END:variables
    private MultivaluePanel multivaluePanel;
    private ContentDialog dialog;

    /**
     * Gets the multivalue panel.
     * 
     * @return the multivalue panel
     */
    public MultivaluePanel getMultivaluePanel() {
        return multivaluePanel;
    }

    /**
     * @return the valueButton
     */
    public JButton getValueButton() {
        return valueButton;
    }

    /**
     * @param valueButton the valueButton to set
     */
    public void setValueButton(javax.swing.JButton valueButton) {
        this.valueButton = valueButton;
    }

    /**
     * @return the dialog
     */
    public ContentDialog getDialog() {
        return dialog;
    }

    /**
     * @param dialog the dialog to set
     */
    public void setDialog(ContentDialog dialog) {
        this.dialog = dialog;
    }

    /**
     * Sets the <code>MandatoryLabelHandler</code>
     * 
     * @param labelHandler the handler
     */
    public void setLabelHandler(MandatoryLabelHandler labelHandler) {
        this.labelHandler = labelHandler;
    }

    /**
     * Returns true, if the <code>MultivalueModel</code> does not contain values.
     * 
     * @return true if model is empty
     */
    public boolean isEmpty() {
        return multivaluePanel.getMultivalueModel().getValues().isEmpty();
    }

    /**
     * Refreshes the current content information explicitly.
     */
    public void refreshContentInformation() {
        contentHasChanged(false, multivaluePanel.retrieveContentInformation());
    }

    /** {@inheritDoc} */
    @Override
    public void contentHasChanged(boolean empty, String text) {
        if (labelHandler != null) {
            labelHandler.handleLabelStateFor(this, empty);
        }
        previewLabel.setText(text);
    }
}