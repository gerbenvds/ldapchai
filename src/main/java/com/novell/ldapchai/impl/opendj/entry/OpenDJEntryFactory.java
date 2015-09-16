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

import com.novell.ldapchai.ChaiEntry;
import com.novell.ldapchai.ChaiFactory;
import com.novell.ldapchai.ChaiGroup;
import com.novell.ldapchai.ChaiUser;
import com.novell.ldapchai.exception.ErrorMap;
import com.novell.ldapchai.impl.edir.EdirErrorMap;
import com.novell.ldapchai.provider.ChaiProvider;

/**
 *
 * @author Robert Meakins
 */
public class OpenDJEntryFactory implements ChaiFactory.ChaiEntryFactory {
    
    private static ErrorMap errorMap;
    
    @Override
    public ChaiUser createChaiUser(final String userDN, final ChaiProvider chaiProvider) {
        return new InetOrgPersonImpl(userDN, chaiProvider);
    }

    @Override
    public ChaiGroup createChaiGroup(final String entryDN, final ChaiProvider provider) {
        return new OpenDJGroup(entryDN, provider);
    }

    @Override
    public ChaiEntry createChaiEntry(final String entryDN, final ChaiProvider provider) {
        return new OpenDJEntryImpl(entryDN, provider);
    }

    @Override
    public ChaiProvider.DIRECTORY_VENDOR getDirectoryVendor() {
        return ChaiProvider.DIRECTORY_VENDOR.FORGEROCK_OPENDJ;
    }

    @Override
    public ErrorMap getErrorMap() {
        if (errorMap == null) {
            errorMap = new EdirErrorMap();
        }
        return errorMap;
    }
}
