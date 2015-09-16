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

import com.novell.ldapchai.ChaiConstant;
import com.novell.ldapchai.ChaiUser;

/**
 * @author Robert Meakins
 */
public interface InetOrgPerson extends OrganizationalPerson, ChaiUser {

    public static final String OBJECT_CLASS_VALUE = ChaiConstant.OBJECTCLASS_BASE_LDAP_USER;
    public static final String ATTR_PASSWORD_CHANGED_TIME = "pwdChangedTime";
    public static final String ATTR_PASSWORD_EXPIRATION_TIME = "ds-pwp-password-expiration-time";
    public static final String ATTR_PASSWORD_RESET = "pwdReset";
    public static final String ATTR_PASSWORD_POLICY_DN = "ds-pwp-password-policy-dn";
    public static final String ATTR_PASSWORD_POLICY_SUBENTRY_DN = "pwdPolicySubentry";
    public static final String ATTR_LAST_LOGIN_TIME_DEFAULT = "ds-pwp-last-login-time";
    
}
