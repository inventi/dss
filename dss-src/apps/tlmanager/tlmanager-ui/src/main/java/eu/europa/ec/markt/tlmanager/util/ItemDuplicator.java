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

package eu.europa.ec.markt.tlmanager.util;

import eu.europa.ec.markt.tlmanager.core.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.DefaultListModel;

/**
 * Small helper class for coping with duplication of items.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class ItemDuplicator {

    private static final String DELIMITER = "_";
    private int startingNumber = 1;
    private DefaultListModel model;
    private Map<String, Integer> lastNumbers;

    /**
     * Instantiates a new item duplicator.
     * 
     * @param model the model
     */
    public ItemDuplicator(DefaultListModel model) {
        this.model = model;
        lastNumbers = new HashMap<String, Integer>();
    }

    private int determineHighestCounter(String selectedValue) {
        int counter = 1;
        for (int i = 0; i < model.getSize(); i++) {
            String entry = (String) model.get(i);
            if (entry.startsWith(selectedValue.substring(0, 2))) {
                String[] split = entry.split(DELIMITER);
                if (split.length > 1) {
                    int number = Integer.parseInt(split[1]);
                    if (number >= counter) {
                        counter = number + 1;
                    }
                }
            }
        }

        return counter;
    }

    /**
     * Duplicates a language entry. It compares the provided selectedValue with the existing values and fishes out the
     * highest existing counter for that entry. The duplicated entry will have a larger counter value.
     * 
     * @param selectedValue the selected value
     * 
     * @return position of the entry in the model
     */
    public int duplicateLanguageEntry(String selectedValue) {
        startingNumber = determineHighestCounter(selectedValue);

        List<String> items = new ArrayList<String>();
        for (int i = 0; i < model.getSize(); i++) {
            items.add((String) model.get(i));
        }

        String newItem = createNewItem(selectedValue);
        items.add(newItem);

        Util.sortItems(items, Configuration.LanguageCodes.getEnglishLanguage());

        int itemLocation = 0;
        model.clear();
        for (int i = 0; i < items.size(); i++) {
            String item = items.get(i);
            model.addElement(item);
            if (item.equals(newItem)) {
                itemLocation = i;
            }
        }

        return itemLocation;
    }

    private String createNewItem(String item) {
        String[] split = item.split(DELIMITER);
        Integer lastNumber = startingNumber;

        if (lastNumbers.containsKey(split[0])) {
            // this item was duplicated before
            lastNumber = lastNumbers.get(split[0]) + 1;
        }
        lastNumbers.put(split[0], lastNumber);

        return new String(split[0] + DELIMITER + lastNumber);
    }

    /**
     * Reinitialises the used hashamp for last numbers.
     */
    public void reInit() {
        lastNumbers = new HashMap<String, Integer>();
    }

    /**
     * Static method for duplicating an entry. If the given entry already contains the used DELIMITER, the string is
     * returned unchanged.
     * 
     * @param entry the entry
     * @param count the count
     * 
     * @return the duplicated entry
     */
    public static String duplicate(String entry, Integer count) {
        if (entry.contains(DELIMITER)) {
            return entry;
        }

        return new String(entry + DELIMITER + count);
    }

    /**
     * Static method for cleaning the delimiter and counter of a provided entry
     * 
     * @param item the item
     * 
     * @return the cleaned string
     */
    public static String cleanItem(String item) {
        String[] split = item.split(DELIMITER);

        return split[0];
    }
}