/*
 * LDAP Chai API
 * Copyright (c) 2006-2010 Novell, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.novell.ldapchai.impl.opendj.entry;

import com.novell.ldapchai.*;
import com.novell.ldapchai.exception.ChaiOperationException;
import com.novell.ldapchai.exception.ChaiUnavailableException;
import com.novell.ldapchai.provider.ChaiProvider;
import com.novell.ldapchai.util.ChaiLogger;
import com.novell.ldapchai.util.DefaultChaiPasswordPolicy;
import com.novell.ldapchai.util.SearchHelper;
import java.util.*;

/**
 * A collection of static helper methods used by the LDAP Chai API.
 * <p/>
 * Generally, consumers of the LDAP Chai API should avoid calling these methods
 * directly.  Where possible, use the {@link com.novell.ldapchai.ChaiEntry}
 * wrappers instead.
 *
 * @author Robert Meakins
 */
public class OpenDJEntries {
    
    public static final String GUID_ATTRIBUTE_NAME = "entryUUID";
    public static final String GROUP_OBJECTCLASS = "groupOfNames";
    public static final String GROUP_UNIQUE_OBJECTCLASS = "groupOfUniqueNames";
    public static final String GROUP_MEMBER_ATTRIBUTE = "member";
    public static final String GROUP_UNIQUE_MEMBER_ATTRIBUTE = "uniqueMember";
    
    private static final ChaiLogger LOGGER = ChaiLogger.getLogger(OpenDJEntries.class);
    
    static String readGuid(final ChaiEntry entry)
            throws ChaiUnavailableException, ChaiOperationException
    {
        return entry.getChaiProvider().readStringAttribute(entry.getEntryDN(), GUID_ATTRIBUTE_NAME);
    }
    
    /**
     * Add a group membership for the supplied user and group. Works for both
     * groupOfNames and groupOfUniqueNames
     * 
     * @param user  A valid {@code ChaiUser}
     * @param group A valid {@code ChaiGroup}
     * @throws com.novell.ldapchai.exception.ChaiUnavailableException If the ldap server(s) are not available
     * @throws com.novell.ldapchai.exception.ChaiOperationException   If there is an error during the operation
     */
    public static void writeGroupMembership(final ChaiUser user, final ChaiGroup group)
            throws ChaiOperationException, ChaiUnavailableException
    {
        if (user == null) {
            throw new NullPointerException("user cannot be null");
        }

        if (group == null) {
            throw new NullPointerException("group cannot be null");
        }

        for (String objectclass : group.readObjectClass()) {
            if (objectclass.equalsIgnoreCase(GROUP_OBJECTCLASS)) {
                group.addAttribute(GROUP_MEMBER_ATTRIBUTE, user.getEntryDN());
                return;
            } else if (objectclass.equalsIgnoreCase(GROUP_UNIQUE_OBJECTCLASS)) {
                group.addAttribute(GROUP_UNIQUE_MEMBER_ATTRIBUTE, user.getEntryDN());
                return;
            }
        }
    }
    
    
    /**
     * Remove a group membership for the supplied user and group. Works for both
     * groupOfNames and groupOfUniqueNames
     *
     * @param user  A valid {@code ChaiUser}
     * @param group A valid {@code ChaiGroup}
     * @throws com.novell.ldapchai.exception.ChaiUnavailableException If the ldap server(s) are not available
     * @throws com.novell.ldapchai.exception.ChaiOperationException   If there is an error during the operation
     */
    public static void removeGroupMembership(final ChaiUser user, final ChaiGroup group)
            throws ChaiOperationException, ChaiUnavailableException
    {
        if (user == null) {
            throw new NullPointerException("user cannot be null");
        }

        if (group == null) {
            throw new NullPointerException("group cannot be null");
        }

        for (String objectclass : group.readObjectClass()) {
            if (objectclass.equalsIgnoreCase(GROUP_OBJECTCLASS)) {
                group.deleteAttribute(GROUP_MEMBER_ATTRIBUTE, user.getEntryDN());
                return;
            } else if (objectclass.equalsIgnoreCase(GROUP_UNIQUE_OBJECTCLASS)) {
                group.deleteAttribute(GROUP_UNIQUE_MEMBER_ATTRIBUTE, user.getEntryDN());
                return;
            }
        }
    }

    public static ChaiPasswordPolicy readPasswordPolicy(final ChaiEntry theUser)
            throws ChaiOperationException, ChaiUnavailableException
    {
        ChaiPasswordPolicy passwordPolicy = null;
        
        final String passwordPolicyDn = theUser.readStringAttribute(InetOrgPerson.ATTR_PASSWORD_POLICY_SUBENTRY_DN);
        
        if (passwordPolicyDn != null && passwordPolicyDn.length() > 0) {
            OpenDJPasswordPolicy openDJPasswordPolicy = new OpenDJPasswordPolicy(passwordPolicyDn, theUser.getChaiProvider());
            openDJPasswordPolicy.processValidators();
                    
            passwordPolicy = DefaultChaiPasswordPolicy.createDefaultChaiPasswordPolicyByRule(openDJPasswordPolicy.getPolicyRules());
        }
        
        return passwordPolicy;
    }
    
    
    /**
     * Convert the commonly used zulu time string to java Date object.
     * See the <a href="http://developer.novell.com/documentation/ndslib/schm_enu/data/sdk5701.html">eDirectory Time attribute syntax definition</a> for more details.
     *
     * @param dateString a date string in the format of "yyyyMMddHHmmss'Z'", for example "199412161032Z"
     * @return A Date object representing the string date
     * @throws IllegalArgumentException if dateString is incorrectly formatted
     */
    public static Date convertZuluToDate(final String dateString)
    {
        if (dateString == null) {
            throw new NullPointerException();
        }

        if (dateString.length() < 15) {
            throw new IllegalArgumentException("zulu date too short");
        }

        if (!dateString.matches("^\\d{14}(\\.\\d{3})?Z")) {
            throw new IllegalArgumentException("zulu date must end in 'Z'");
        }

        // Zulu TimeZone is same as GMT or UTC
        final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("Zulu"));

        cal.set(Calendar.YEAR, Integer.parseInt(dateString.substring(0, 4)));
        cal.set(Calendar.MONTH, Integer.parseInt(dateString.substring(4, 6)) - 1);
        cal.set(Calendar.DATE, Integer.parseInt(dateString.substring(6, 8)));
        cal.set(Calendar.HOUR_OF_DAY, Integer.parseInt(dateString.substring(8, 10)));
        cal.set(Calendar.MINUTE, Integer.parseInt(dateString.substring(10, 12)));
        cal.set(Calendar.SECOND, Integer.parseInt(dateString.substring(12, 14)));
        if (dateString.length() == 19) {
            cal.set(Calendar.MILLISECOND, Integer.parseInt(dateString.substring(15, 18)));
        }

        return cal.getTime();
    }
    
    //read all attribute values from object at dn.
    static Map<String, List<String>> getAllAttributesForDn(String dn, ChaiProvider chaiProvider) throws ChaiUnavailableException, ChaiOperationException {
        final SearchHelper searchHelper = new SearchHelper();
        searchHelper.setFilter(SearchHelper.DEFAULT_FILTER);
        searchHelper.setSearchScope(ChaiProvider.SEARCH_SCOPE.BASE);
        
        final Map<String, Map<String, List<String>>> bigResults = chaiProvider.searchMultiValues(dn, searchHelper);
        final Map<String, List<String>> results = bigResults.get(dn);
        
        return results;
    }

    /*
     * Reads a time interval specified in OpenDJ's format, e.g. "3d" is 3 days.
     * 
     * @param value The String value of the attribute
     * @returns the number of seconds that the time represents
     */
    public static int readTimeInterval(final String value) {
        if (value != null && value.length() > 0) {
            try {
                String trimmedValue = value.trim();
                int number = Integer.parseInt(trimmedValue);
                String unit = trimmedValue.substring(trimmedValue.lastIndexOf(" ") + 1);

                // If we also got the digit by accident, remove it
                while ("[0-9]".matches(unit.substring(0, 1))) {
                    unit = unit.substring(1);
                }

                int unitMultiplier;
                if (unit.equalsIgnoreCase("s") || unit.equalsIgnoreCase("seconds")) {
                    unitMultiplier = 1;
                } else if (unit.equalsIgnoreCase("m") || unit.equalsIgnoreCase("minutes")) {
                    unitMultiplier = 60;
                } else if (unit.equalsIgnoreCase("h") || unit.equalsIgnoreCase("hours")) {
                    unitMultiplier = 3600;
                } else if (unit.equalsIgnoreCase("d") || unit.equalsIgnoreCase("days")) {
                    unitMultiplier = 86400;
                } else if (unit.equalsIgnoreCase("w") || unit.equalsIgnoreCase("weeks")) {
                    unitMultiplier = 604800;
                } else {
                    // Assume the unit is seconds
                    unitMultiplier = 1;
                }
                return number * unitMultiplier;
            } catch (Exception e) {
                LOGGER.error("error while converting time interval to seconds", e);
            }
        }
        return 0;
    }
    
}
