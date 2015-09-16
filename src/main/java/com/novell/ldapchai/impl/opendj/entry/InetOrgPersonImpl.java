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

import com.novell.ldapchai.ChaiGroup;
import com.novell.ldapchai.ChaiPasswordPolicy;
import com.novell.ldapchai.ChaiUser;
import com.novell.ldapchai.exception.ChaiOperationException;
import com.novell.ldapchai.exception.ChaiPasswordPolicyException;
import com.novell.ldapchai.exception.ChaiUnavailableException;
import com.novell.ldapchai.impl.AbstractChaiUser;
import com.novell.ldapchai.provider.ChaiProvider;
import com.novell.ldapchai.util.ChaiLogger;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author Robert Meakins
 */
class InetOrgPersonImpl extends AbstractChaiUser implements InetOrgPerson, ChaiUser {
    
    private static final ChaiLogger LOGGER = ChaiLogger.getLogger(OpenDJPasswordPolicy.class);
    
    @Override
    public String getLdapObjectClassName()
    {
        return InetOrgPerson.OBJECT_CLASS_VALUE;
    }

    InetOrgPersonImpl(final String userDN, final ChaiProvider chaiProvider)
    {
        super(userDN, chaiProvider);
    }

    @Override
    public ChaiPasswordPolicy getPasswordPolicy()
            throws ChaiUnavailableException, ChaiOperationException
    {
        return OpenDJEntries.readPasswordPolicy(this);
    }

    @Override
    public boolean testPassword(String passwordValue)
            throws ChaiUnavailableException, ChaiPasswordPolicyException
    {
        throw new UnsupportedOperationException("InetOrgPersonImpl#testPassword not implemented in opendj-impl ldapChai API");
    }

    @Override
    public boolean testPasswordPolicy(final String password)
            throws ChaiUnavailableException, ChaiPasswordPolicyException
    {
        return false;
    }

    @Override
    public final void addGroupMembership(final ChaiGroup theGroup)
            throws ChaiOperationException, ChaiUnavailableException
    {
        OpenDJEntries.writeGroupMembership(this, theGroup);
    }

    @Override
    public void removeGroupMembership(final ChaiGroup theGroup)
            throws ChaiOperationException, ChaiUnavailableException
    {
        OpenDJEntries.removeGroupMembership(this, theGroup);
    }

    @Override
    public final String readPassword()
            throws ChaiUnavailableException, ChaiOperationException
    {
        throw new UnsupportedOperationException("InetOrgPersonImpl#readPassword not implemented in opendj-impl ldapChai API");
    }

    @Override
    public boolean isPasswordExpired()
            throws ChaiUnavailableException, ChaiOperationException
    {
        if ("true".equalsIgnoreCase(readStringAttribute(ATTR_PASSWORD_RESET))) {
            return true;
        }
        
        final Date expireDate = readPasswordExpirationDate();

        if (expireDate == null) {
            return false;
        }

        return expireDate.before(new Date());
    }

    @Override
    public final Date readLastLoginTime()
            throws ChaiOperationException, ChaiUnavailableException
    {
        try {
            // Try to read password policy to get the name of the last login
            // time attribute and the last login time format
            final String passwordPolicyDn = readStringAttribute(InetOrgPerson.ATTR_PASSWORD_POLICY_SUBENTRY_DN);
            OpenDJPasswordPolicy openDJPasswordPolicy = new OpenDJPasswordPolicy(passwordPolicyDn, getChaiProvider());
            String lastLoginTimeAttribute = openDJPasswordPolicy.getLastLoginTimeAttribute();
            String lastLoginTimeFormat = openDJPasswordPolicy.getLastLoginTimeFormat();
            
            DateFormat df = new SimpleDateFormat(readStringAttribute(lastLoginTimeFormat));
            return df.parse(readStringAttribute(lastLoginTimeAttribute));
            
            
        } catch (Exception e) {
            LOGGER.warn("failed to read password policy while trying to obtain last login time - attempting to read default attribute.", e);
            try {
                return readDateAttribute(ATTR_LAST_LOGIN_TIME_DEFAULT);
            } catch (ChaiOperationException coe) {
                LOGGER.error("Could not read last login time - returning epoch", coe);
                return new Date(0);
            }
        }
    }

    @Override
    public final void changePassword(final String oldPassword, final String newPassword)
            throws ChaiUnavailableException, ChaiPasswordPolicyException, ChaiOperationException
    {
        try {
            writeStringAttribute(ATTR_PASSWORD, newPassword);
        } catch (ChaiOperationException e) {
            throw ChaiPasswordPolicyException.forErrorMessage(e.getMessage());
        }
    }

    /**
    * Sets the user's pwdReset attribute to "true". This attribute only takes
    * effect if the user has been configured with a password policy supporting
    * password expiration.
    */
    @Override
    public void expirePassword()
            throws ChaiOperationException, ChaiUnavailableException
    {
        this.writeStringAttribute(ATTR_PASSWORD_RESET, "true");
    }

    /**
    * Reads the user's ds-pwd-password-expiration-time attribute. Note that this
    * attribute is first enabled in OpenDJ 2.5.0-Xpress1
    */
    @Override
    public Date readPasswordExpirationDate() throws ChaiUnavailableException, ChaiOperationException {
        return readDateAttribute(ATTR_PASSWORD_EXPIRATION_TIME);
    }

    @Override
    public String readGUID()
            throws ChaiOperationException, ChaiUnavailableException
    {
        return OpenDJEntries.readGuid(this);
    }

    @Override
    public boolean isAccountEnabled() throws ChaiOperationException, ChaiUnavailableException {
        return true;
    }

    @Override
    public Date readPasswordModificationDate() throws ChaiOperationException, ChaiUnavailableException {
        return readDateAttribute(ATTR_PASSWORD_CHANGED_TIME);
    }

    @Override
    public Date readDateAttribute(final String attributeName)
            throws ChaiUnavailableException, ChaiOperationException
    {
        final String value = this.readStringAttribute(attributeName);
        if (value != null) {
            return OpenDJEntries.convertZuluToDate(value);
        }
        return null;
    }
}
